import io
import json
import os
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

from omp_hindsight_guard import cli, shellhooks
from omp_hindsight_guard.config import ENV_CONFIG_DIR, load_config, load_keys
from omp_hindsight_guard.init import create_key, init_config, parse_bank_args
from tests.conftest import free_port
from tests.helpers import make_setup


@pytest.fixture
def cfg_dir(tmp_path, monkeypatch):
	directory = tmp_path / "cfg"
	monkeypatch.setenv(ENV_CONFIG_DIR, str(directory))
	return directory


def mode(path):
	return stat.S_IMODE(path.stat().st_mode)


def test_init_writes_config_and_private_keys_and_never_prints_them(cfg_dir):
	out = io.StringIO()
	banks = parse_bank_args(["work=~/code/work", "work=~/code/more", "home=~/notes"])
	assert banks == {"work": ["~/code/work", "~/code/more"], "home": ["~/notes"]}
	assert init_config(cfg_dir, banks, out) == 0
	config = load_config(cfg_dir / "banks.json")
	assert [b.name for b in config.banks] == ["work", "home"]
	assert config.bank("work").roots == ("~/code/work", "~/code/more")
	keys = load_keys(config)  # distinct, 0600, well formed
	assert (
		mode(cfg_dir / "banks.json") == 0o600 and mode(cfg_dir) == 0o700 and mode(cfg_dir / "keys") == 0o700
	)
	for key in (keys.upstream, *keys.banks.values()):
		assert len(key) == 64 and key not in out.getvalue()
	assert "created" in out.getvalue() and "docs/server-setup.md" in out.getvalue()


def test_init_never_overwrites(cfg_dir, capsys):
	assert init_config(cfg_dir, {"work": ["~/code/work"]}, io.StringIO()) == 0
	first = (cfg_dir / "banks.json").read_text()
	key = (cfg_dir / "keys" / "bank-work.key").read_text()
	assert init_config(cfg_dir, {"other": ["~/x"]}, io.StringIO()) == 2
	assert "already exists" in capsys.readouterr().err
	assert (cfg_dir / "banks.json").read_text() == first
	assert not create_key(cfg_dir / "keys" / "bank-work.key")
	assert (cfg_dir / "keys" / "bank-work.key").read_text() == key


def test_init_rejects_bad_input_before_writing(cfg_dir, capsys):
	assert init_config(cfg_dir, {}, io.StringIO()) == 2
	assert init_config(cfg_dir, {"bad name": ["~/x"]}, io.StringIO()) == 2
	assert init_config(cfg_dir, {"ok": ["relative"]}, io.StringIO()) == 2
	assert not cfg_dir.exists()
	with pytest.raises(Exception, match="NAME=ROOT"):
		parse_bank_args(["nonsense"])
	capsys.readouterr()


def test_bank_named_upstream_does_not_share_the_upstream_key(cfg_dir):
	assert init_config(cfg_dir, {"upstream": ["~/x"]}, io.StringIO()) == 0
	assert load_keys(load_config(cfg_dir / "banks.json")).banks["upstream"]  # distinct files, distinct keys


def test_overlays_route_and_prune_commands(cfg_dir, scratch_home, capsys):
	make_setup(cfg_dir, {"alpha": ["~/work/a"], "beta": ["~/work/b"]})
	(scratch_home / "work/a/sub").mkdir(parents=True)
	assert cli.main(["overlays"]) == 0
	out = cfg_dir / "overlays"
	assert sorted(p.name for p in out.iterdir()) == ["alpha.yml", "beta.yml", "routes.tsv"]
	capsys.readouterr()
	assert cli.main(["route", str(scratch_home / "work/a/sub")]) == 0
	assert capsys.readouterr().out == "alpha\n"
	assert cli.main(["route", str(scratch_home)]) == 1
	assert capsys.readouterr().out == "-\n"
	# Drop a bank: its overlay is reported, and removed only with --prune.
	make_setup(cfg_dir, {"alpha": ["~/work/a"]})
	assert cli.main(["overlays"]) == 0
	assert "stale overlay" in capsys.readouterr().out and (out / "beta.yml").exists()
	assert cli.main(["overlays", "--prune"]) == 0
	assert not (out / "beta.yml").exists() and (out / "alpha.yml").exists()
	assert cli.main(["overlays", "--url", "http://memory.example"]) == 2  # cleartext to a remote host


def test_missing_config_is_a_clean_error(cfg_dir, capsys):
	assert cli.main(["overlays"]) == 2
	assert "init" in capsys.readouterr().err


def test_import_passes_arguments_and_help_through(cfg_dir, capsys):
	with pytest.raises(SystemExit) as err:
		cli.main(["import", "--help"])
	assert err.value.code == 0 and "--count-unsynced" in capsys.readouterr().out
	make_setup(cfg_dir, {"alpha": ["~/work/a"]})
	assert cli.main(["import", "--root", str(cfg_dir / "nope")]) == 2
	assert "no mnemopi banks root" in capsys.readouterr().err


# --- hooks ---------------------------------------------------------------------------------------------------


def test_hook_prints_the_line_and_writes_nothing_to_startup_files_by_default(cfg_dir, scratch_home, capsys):
	for shell, name in (
		("zsh", "omp-hindsight-guard.zsh"),
		("bash", "omp-hindsight-guard.bash"),
		("fish", "omp-hindsight-guard.fish"),
	):
		assert cli.main(["hook", shell]) == 0
		text = capsys.readouterr().out
		installed = cfg_dir / "hooks" / name
		assert installed.read_text() == shellhooks.hook_text(shell) and f'source "{installed}"' in text
	assert cli.main(["hook", "shim"]) == 0
	shim = cfg_dir / "shim" / "omp"
	assert os.access(shim, os.X_OK) and f'export PATH="{shim.parent}":"$PATH"' in capsys.readouterr().out
	assert sorted(p.name for p in scratch_home.iterdir()) == []  # no rc file created


def test_hook_install_asks_then_appends_once_and_uninstall_removes(cfg_dir, scratch_home, capsys):
	rc = scratch_home / ".zshrc"
	rc.write_text("export A=1\n")
	args = ["hook", "zsh", "--install", "--rc", str(rc)]
	assert cli.main(args) == 2  # no terminal to ask on, no --yes
	assert rc.read_text() == "export A=1\n" and "--yes" in capsys.readouterr().err
	assert cli.main([*args, "--yes"]) == 0
	text = rc.read_text()
	assert (
		text.startswith("export A=1\n") and text.count(shellhooks.BEGIN) == 1 and text.count("source ") == 1
	)
	assert cli.main([*args, "--yes"]) == 0 and rc.read_text() == text  # idempotent
	assert "already present" in capsys.readouterr().out
	assert cli.main(["hook", "zsh", "--uninstall", "--rc", str(rc)]) == 0
	assert rc.read_text() == "export A=1\n"
	assert cli.main(["hook", "zsh", "--uninstall", "--rc", str(rc)]) == 0  # nothing left, still fine


def test_hook_install_answers_from_a_terminal(cfg_dir, scratch_home):
	class Tty(io.StringIO):
		def isatty(self):
			return True

	rc = scratch_home / ".bashrc"
	out = io.StringIO()
	assert (
		shellhooks.hook_command(
			"bash", cfg_dir, install=True, rc=rc, out=out, stdin=Tty("n\n"), home=scratch_home
		)
		== 0
	)
	assert not rc.exists() and "not appended" in out.getvalue()
	assert (
		shellhooks.hook_command(
			"bash", cfg_dir, install=True, rc=rc, out=io.StringIO(), stdin=Tty("y\n"), home=scratch_home
		)
		== 0
	)
	assert shellhooks.BEGIN in rc.read_text()


def test_shim_install_needs_an_rc_and_fish_gets_fish_syntax(cfg_dir, scratch_home, capsys):
	assert cli.main(["hook", "shim", "--install"]) == 2
	assert "--rc" in capsys.readouterr().err
	rc = scratch_home / ".config/fish/config.fish"
	assert cli.main(["hook", "shim", "--install", "--yes", "--rc", str(rc)]) == 0
	assert "fish_add_path --prepend --move" in rc.read_text()
	assert cli.main(["hook", "shim", "--uninstall"]) == 2


def test_startup_line_quotes_paths_safely(tmp_path):
	odd = tmp_path / 'we"ird $dir' / "x"
	line = shellhooks.startup_line("zsh", odd, "posix", home=tmp_path / "elsewhere")
	assert line == 'source "' + str(odd).replace('"', '\\"').replace("$", "\\$") + '"'
	inside = tmp_path / "h" / ".config" / "g" / "x.zsh"
	assert (
		shellhooks.startup_line("zsh", inside, "posix", home=tmp_path / "h")
		== 'source "$HOME/.config/g/x.zsh"'
	)


# --- per-repo link mode --------------------------------------------------------------------------------------


@pytest.fixture
def linked(cfg_dir, scratch_home):
	config = make_setup(cfg_dir, {"alpha": ["~/work/alpha"], "beta": ["~/work/beta"]})
	assert cli.main(["overlays"]) == 0
	repo = scratch_home / "work/alpha/app"
	repo.mkdir(parents=True)
	subprocess.run(["git", "init", "-q", str(repo)], check=True)
	return config, repo, cfg_dir / "overlays"


def test_link_symlinks_the_overlay_and_excludes_it_from_git(linked, capsys):
	_config, repo, overlays = linked
	assert cli.main(["link", str(repo)]) == 0
	text = capsys.readouterr().out
	target = repo / ".omp" / "config.yml"
	assert target.is_symlink() and os.path.realpath(target) == os.path.realpath(overlays / "alpha.yml")
	assert "exact folder" in text and "HINDSIGHT_API_URL" in text and "${VAR}" in text
	exclude = (repo / ".git" / "info" / "exclude").read_text()
	assert exclude.splitlines().count("/.omp/config.yml") == 1
	status = subprocess.run(
		["git", "-C", str(repo), "status", "--porcelain"], capture_output=True, text=True, check=True
	)
	assert ".omp" not in status.stdout
	assert cli.main(["link", str(repo)]) == 0  # idempotent
	assert (repo / ".git" / "info" / "exclude").read_text().splitlines().count("/.omp/config.yml") == 1
	assert "already linked" in capsys.readouterr().out


def test_link_picks_the_bank_from_the_roots_or_the_flag(linked, scratch_home, capsys):
	_config, _repo, overlays = linked
	outside = scratch_home / "elsewhere"
	outside.mkdir()
	assert cli.main(["link", str(outside)]) == 2 and "outside every bank root" in capsys.readouterr().err
	assert cli.main(["link", str(outside), "--bank", "beta"]) == 0
	assert os.path.realpath(outside / ".omp/config.yml") == os.path.realpath(overlays / "beta.yml")
	assert "not a git work tree" in capsys.readouterr().out
	assert cli.main(["link", str(outside), "--bank", "nope"]) == 2


def test_link_never_touches_an_existing_project_config(linked, capsys):
	_config, repo, _overlays = linked
	(repo / ".omp").mkdir()
	(repo / ".omp" / "config.yml").write_text("memory:\n  backend: off\n")
	assert cli.main(["link", str(repo)]) == 2
	assert "left alone" in capsys.readouterr().err
	assert (repo / ".omp" / "config.yml").read_text() == "memory:\n  backend: off\n"
	assert cli.main(["link", str(repo), "--remove"]) == 2  # not a symlink: not ours to remove
	assert (repo / ".omp" / "config.yml").exists()


def test_link_remove_only_removes_this_tools_link(linked, tmp_path, capsys):
	_config, repo, _overlays = linked
	assert cli.main(["link", str(repo)]) == 0
	assert cli.main(["link", str(repo), "--remove"]) == 0
	assert not (repo / ".omp").exists()
	foreign = tmp_path / "foreign.yml"
	foreign.write_text("x: 1\n")
	(repo / ".omp").mkdir()
	(repo / ".omp" / "config.yml").symlink_to(foreign)
	assert cli.main(["link", str(repo), "--remove"]) == 2
	assert (repo / ".omp" / "config.yml").is_symlink() and "does not point into" in capsys.readouterr().err


def test_link_needs_generated_overlays(cfg_dir, scratch_home, capsys):
	make_setup(cfg_dir, {"alpha": ["~/work/alpha"]})
	repo = scratch_home / "work/alpha"
	repo.mkdir(parents=True)
	assert cli.main(["link", str(repo)]) == 2 and "overlays" in capsys.readouterr().err


# --- the proxy as a process ----------------------------------------------------------------------------------


def test_proxy_command_serves_and_refuses_remote_listen_unless_allowed(tmp_path, scratch_home):
	cfg_dir = tmp_path / "cfg"
	port = free_port()
	make_setup(cfg_dir, {"alpha": ["~/work/a"]}, listen_port=port)
	env = {**os.environ, ENV_CONFIG_DIR: str(cfg_dir), "HOME": str(scratch_home)}
	proc = subprocess.Popen(
		[sys.executable, "-m", "omp_hindsight_guard.cli", "proxy"],
		env=env,
		stdout=subprocess.PIPE,
		stderr=subprocess.PIPE,
		text=True,
	)
	try:
		deadline = time.time() + 15
		status = None
		while time.time() < deadline and status is None:
			try:
				req = urllib.request.Request(f"http://127.0.0.1:{port}/v1/default/banks/alpha/memories/list")
				opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
				opener.open(req, timeout=2)
			except urllib.error.HTTPError as err:
				status = err.code
			except OSError:
				time.sleep(0.1)
		assert status == 401  # up, and no key means no entry
	finally:
		proc.terminate()
		proc.wait(timeout=10)
	data = json.loads((cfg_dir / "banks.json").read_text())
	data["proxy"]["listen_host"] = "0.0.0.0"
	(cfg_dir / "banks.json").write_text(json.dumps(data))
	done = subprocess.run(
		[sys.executable, "-m", "omp_hindsight_guard.cli", "proxy"],
		env=env,
		capture_output=True,
		text=True,
		timeout=30,
	)
	assert done.returncode == 2 and "loopback" in done.stderr
	assert done.stdout == ""


def test_redact_command_filters_stdin(tmp_path, scratch_home):
	secret = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
	done = subprocess.run(
		[sys.executable, "-m", "omp_hindsight_guard.cli", "redact"],
		input=f"token {secret} ok\n",
		capture_output=True,
		text=True,
		timeout=30,
		env={**os.environ, "HOME": str(scratch_home)},
	)
	assert done.stdout == "token [REDACTED:github-token] ok\n" and secret not in done.stderr
	assert "redactions: github-token=1" in done.stderr
