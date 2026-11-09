# ruff: noqa: F811
"""Third review (hooks): block mode with unknown configuration (R10), one routing answer for Python and every launcher
(R11), and the probe cache in a state directory nobody else may write to (R12). Each ran against zsh, bash, bash 3.2,
fish (where installed) and the PATH shim. Each failed before its fix."""

import os
import re
import stat
import time

import pytest

from omp_hindsight_guard import routing
from tests.test_hook import (  # noqa: F401
	BLOCK,
	launch,
	overlay_args,
	run,
	runner,
	server,
	state_files,
	with_url,
	world,
)

DOWN = "http://127.0.0.1:9"


# --- R10: block mode must not treat "I do not know" as permission to launch -------------------------------------


def test_r10_block_mode_refuses_without_a_routing_table_and_permissive_mode_does_not(runner, world):
	world["routes"].unlink()
	cwd = world["home"] / "work/other"
	proc, _ = launch(runner, world, cwd, extra=BLOCK, check=False)
	assert proc.returncode == 75 and proc.stdout == ""  # the fake omp never ran
	assert "routing table" in proc.stderr and "missing or unreadable" in proc.stderr
	assert "refusing to start" in proc.stderr
	# not asking for block: the same launch is unchanged and silent, as documented
	proc, _ = launch(runner, world, cwd)
	assert proc.stderr == "" and proc.stdout.splitlines()[0] == "argv:"


def test_r10_block_mode_refuses_a_routing_table_with_no_usable_entry(runner, world):
	world["routes"].write_text("# nothing here\n\nbad name\t~/x\nbeta\trelative/path\n")
	proc, _ = launch(runner, world, world["home"] / "work/other", extra=BLOCK, check=False)
	assert proc.returncode == 75 and proc.stdout == "" and "malformed entry" in proc.stderr
	proc, _ = launch(runner, world, world["home"] / "work/other")
	assert proc.stderr == ""


def test_r10_block_mode_refuses_an_overlay_that_names_no_server(runner, world):
	"""The default fixture overlay carries no apiUrl: nothing says where omp's memory would go."""
	proc, _ = launch(runner, world, world["home"] / "work/beta-site", extra=BLOCK, check=False)
	assert proc.returncode == 75 and proc.stdout == "" and "names no apiUrl" in proc.stderr
	# permissive mode keeps the overlay, as before
	assert run(runner, world, world["home"] / "work/beta-site")[0] == overlay_args(world, "beta")


def test_r10_a_valid_table_that_places_the_folder_outside_every_bank_is_still_unchanged(runner, world):
	argv, env = run(runner, world, world["home"] / "work/other", extra=BLOCK)
	assert (argv, env) == ("argv:", "env:/stale/overlay.yml")


# --- R11: Python and every launcher answer the same question the same way ----------------------------------------


def test_r11_launchers_and_python_choose_the_same_bank_for_every_directory(runner, world, tmp_path):
	home = world["home"]
	for name in (
		"work/alpha-app/inner/deep",
		"work/alpha-app-extra",
		"work/real-root/sub",
		"work/beta-site/a b",
	):
		(home / name).mkdir(parents=True, exist_ok=True)
	(home / "work/linkroot").symlink_to(home / "work/real-root")
	(home / "work/escape").symlink_to(home / "work/alpha-app/inner")
	(home / "work/alpha-app/caf\u00e9").mkdir()
	for bank in ("gamma", "delta"):
		(world["overlays"] / f"{bank}.yml").write_text("memory:\n  backend: hindsight\n")
	banks = [
		("alpha", "~/work/alpha-app"),
		("alpha", "~/work/linkroot"),
		("beta", "~/work/alpha-app/inner"),  # longer root, inside another bank's
		("beta", "~/work/beta-site/"),  # trailing slash as hand-written
		("gamma", "~/work/../work/tools"),  # the same directory as delta's: equally long, so ambiguous
		("delta", "~/work/tools"),
	]
	world["routes"].write_text("".join(f"{b}\t{r}\n" for b, r in banks))
	cases = [
		"work/alpha-app",
		"work/alpha-app/ui",
		"work/alpha-app/inner",
		"work/alpha-app/inner/deep",
		"work/alpha-app/caf\u00e9",
		"work/alpha-app-extra",  # a string prefix of a root, not a folder inside it
		"work/linkroot",
		"work/linkroot/sub",
		"work/real-root/sub",  # reached through the root's target
		"work/escape",  # a link into a longer root
		"work/beta-site",
		"work/beta-site/a b",
		"work/tools",  # two banks, one directory
		"work/other",
		"work",
	]
	for relative in cases:
		cwd = home / relative
		found = routing.route(cwd, banks, home)
		if found.ambiguous:
			expected = "argv:"
		else:
			expected = overlay_args(world, found.bank) if found.bank else "argv:"
		assert run(runner, world, cwd)[0] == expected, relative


def test_r11_the_configuration_refuses_roots_a_launcher_could_not_reproduce(tmp_path):
	from omp_hindsight_guard import config as cfg

	for root in (
		"~/missing/../project",
		"~/./project",
		"~//project",
		"/srv/../etc/project",
		"~/proj\u00e9ct",
	):
		with pytest.raises(cfg.ConfigError):
			cfg.normalize_root(root, "banks.a.roots")


# --- R12: the probe cache lives in a directory nobody else may write to ----------------------------------------------


def cache_name(url):
	return "reach-" + re.sub(r"[^A-Za-z0-9]", "_", url)


def with_state(tmp_path, mode=0o700):
	state = tmp_path / "state"
	state.mkdir(mode=mode)
	state.chmod(mode)
	return state, {"OMP_HINDSIGHT_GUARD_STATE_DIR": str(state)}


def test_r12_a_symlinked_state_directory_is_neither_written_nor_changed(runner, world, tmp_path):
	with_url(world, DOWN)
	victim = tmp_path / "victim"
	victim.mkdir()
	victim.chmod(0o755)
	link = tmp_path / "state-link"
	link.symlink_to(victim)
	launch(
		runner, world, world["home"] / "work/beta-site", extra={"OMP_HINDSIGHT_GUARD_STATE_DIR": str(link)}
	)
	assert list(victim.iterdir()) == []
	assert stat.S_IMODE(victim.stat().st_mode) == 0o755  # not chmod'ed through the link


def test_r12_a_group_writable_state_directory_is_not_trusted(runner, world, tmp_path):
	with_url(world, DOWN)
	state, extra = with_state(tmp_path, 0o770)
	forged = state / cache_name(DOWN)
	forged.write_text(f"{int(time.time())} up\n")  # claims the server is up
	forged.chmod(0o600)
	proc, _ = launch(runner, world, world["home"] / "work/beta-site", extra=extra)
	assert "unreachable" in proc.stderr  # the forged cache was not believed
	assert forged.read_text().endswith(" up\n") and sorted(p.name for p in state.iterdir()) == [forged.name]


def test_r12_a_symlinked_cache_entry_is_replaced_not_followed(runner, world, tmp_path):
	with_url(world, DOWN)
	state, extra = with_state(tmp_path)
	victim = tmp_path / "victim.txt"
	victim.write_text("precious\n")
	entry = state / cache_name(DOWN)
	entry.symlink_to(victim)
	launch(runner, world, world["home"] / "work/beta-site", extra=extra)
	assert victim.read_text() == "precious\n"
	assert not entry.is_symlink() and entry.is_file()


def test_r12_the_cache_is_written_through_an_unpredictable_name_and_leaves_nothing_behind(
	runner, world, tmp_path
):
	with_url(world, DOWN)
	state, extra = with_state(tmp_path)
	launch(runner, world, world["home"] / "work/beta-site", extra=extra)
	assert sorted(p.name for p in state.iterdir()) == [cache_name(DOWN)]
	assert stat.S_IMODE((state / cache_name(DOWN)).stat().st_mode) == 0o600
	assert os.stat(state).st_uid == os.getuid() and stat.S_IMODE(state.stat().st_mode) == 0o700


# --- second verification pass: N3 (a partly malformed table) and N8 (a failed permission probe) ----------------------


def test_n3_block_mode_refuses_a_table_with_any_malformed_entry(runner, world):
	"""One valid entry used to make the table "usable": a launch in the folder of the broken one ran unchanged."""
	for text in (
		"beta\t~/work/beta-site\nalpha\n",  # a bank with no root
		"beta\t~/work/beta-site\nalpha\trelative/path\n",
		"beta\t~/work/beta-site\nbad name\t~/work/alpha-app\n",
		"beta\t~/work/beta-site\n\t~/work/alpha-app\n",
	):
		world["routes"].write_text(text)
		proc, _ = launch(runner, world, world["home"] / "work/alpha-app/ui", extra=BLOCK, check=False)
		assert proc.returncode == 75 and proc.stdout == "", text
		assert "malformed entry" in proc.stderr, text
		# the healthy part still routes when nobody asked for block mode
		argv, _ = run(runner, world, world["home"] / "work/beta-site")
		assert argv == overlay_args(world, "beta")
		proc, _ = launch(runner, world, world["home"] / "work/alpha-app/ui")
		assert proc.stderr == "" and proc.stdout.splitlines()[0] == "argv:"


def test_n3_comments_and_blank_lines_are_not_malformed(runner, world):
	world["routes"].write_text("# routes\n\nbeta\t~/work/beta-site\n\n# end\n")
	with_url(world, DOWN)
	proc, _ = launch(runner, world, world["home"] / "work/other", extra=BLOCK)
	assert proc.stderr == ""  # a valid table placing the folder outside every bank
