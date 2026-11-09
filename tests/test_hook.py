"""The shell hooks (zsh, bash, fish) and the PATH shim, run in real shells against a fake `omp` that reports its
argv and environment. Every behaviour is proven for every available shell by the same tests."""

import http.server
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

import omp_hindsight_guard
from omp_hindsight_guard import routing
from omp_hindsight_guard.config import parse_config

HOOKS = Path(omp_hindsight_guard.__file__).resolve().parent / "hooks"
FAKE_OMP = """#!/bin/sh
printf 'argv:'
for a in "$@"; do printf ' [%s]' "$a"; done
printf '\\n'
if [ -n "${PI_CONFIG_FILES+x}" ]; then printf 'env:%s\\n' "$PI_CONFIG_FILES"; else printf 'env:unset\\n'; fi
"""
BANKS_JSON = {
	"version": 1,
	"proxy": {"upstream_key_file": "u.key"},
	"banks": {
		"alpha": {"key_file": "a.key", "roots": ["~/work/alpha-app", "~/work/tools"]},
		"beta": {"key_file": "b.key", "roots": ["~/work/beta-site"]},
	},
}


class Runner:
	"""How one shell launches `omp` in a directory."""

	def __init__(self, name, argv_prefix, hook):
		self.name, self.prefix, self.hook = name, argv_prefix, hook

	def available(self):
		return shutil.which(self.prefix[0]) is not None or Path(self.prefix[0]).exists()

	def command(self, world, cwd, args):
		if self.name == "shim":
			return [str(world["shim"]), *args]
		script = {
			"zsh": 'source "$1"; cd "$2" || exit 9; shift 2; omp "$@"',
			"fish": "source $argv[1]; cd $argv[2]; or exit 9; omp $argv[3..-1]",
		}.get(self.name, 'source "$1"; cd "$2" || exit 9; shift 2; omp "$@"')
		tail = [str(self.hook), str(cwd), *args]
		if self.name == "fish":
			return [*self.prefix, script, *tail]
		return [*self.prefix, script, self.name, *tail]


RUNNERS = [
	Runner("zsh", ["zsh", "-f", "-c"], HOOKS / "omp-hindsight-guard.zsh"),
	Runner(
		"bash",
		[shutil.which("bash") or "bash", "--noprofile", "--norc", "-c"],
		HOOKS / "omp-hindsight-guard.bash",
	),
	Runner("bash3", ["/bin/bash", "--noprofile", "--norc", "-c"], HOOKS / "omp-hindsight-guard.bash"),
	Runner("fish", ["fish", "--no-config", "-c"], HOOKS / "omp-hindsight-guard.fish"),
	Runner("shim", ["bash"], HOOKS / "omp-shim.sh"),
]


@pytest.fixture(params=RUNNERS, ids=[r.name for r in RUNNERS])
def runner(request):
	if not request.param.available():
		pytest.skip(f"{request.param.name} is not installed")
	return request.param


@pytest.fixture
def world(tmp_path):
	home = tmp_path / "home"
	for d in ("work/beta-site/web", "work/alpha-app/ui", "work/tools", "work/other"):
		(home / d).mkdir(parents=True)
	overlays = tmp_path / "overlays"
	overlays.mkdir()
	for bank in ("alpha", "beta"):
		(overlays / f"{bank}.yml").write_text("memory:\n  backend: hindsight\n")
	routes = overlays / "routes.tsv"
	routes.write_text(routing.routes_table(parse_config(BANKS_JSON, tmp_path / "banks.json")))
	bin_dir = tmp_path / "bin"
	bin_dir.mkdir()
	fake = bin_dir / "omp"
	fake.write_text(FAKE_OMP)
	fake.chmod(0o755)
	shim_dir = tmp_path / "shim"
	shim_dir.mkdir()
	shim = shim_dir / "omp"
	shim.write_text((HOOKS / "omp-shim.sh").read_text())
	shim.chmod(0o755)
	return {
		"home": home,
		"overlays": overlays,
		"routes": routes,
		"bin": bin_dir,
		"shim": shim,
		"shim_dir": shim_dir,
	}


def environment(world, runner, extra=None, inherited="/stale/overlay.yml"):
	# The shim directory is on PATH only when the shim is what is being tested: a shell function and the shim
	# must not both wrap omp (the docs say use one).
	shim_path = f"{world['shim_dir']}:" if runner.name == "shim" else ""
	env = {
		"HOME": str(world["home"]),
		# the helper the thin launchers call (omp-hindsight-guard-pick) lives next to this interpreter
		"PATH": f"{shim_path}{world['bin']}:{Path(sys.executable).parent}:/usr/bin:/bin",
		"OMP_HINDSIGHT_GUARD_OVERLAY_DIR": str(world["overlays"]),
		**(extra or {}),
	}
	env = {k: v for k, v in env.items() if v is not None}  # an extra of None removes the variable
	if inherited is not None:
		env["PI_CONFIG_FILES"] = inherited
	return env


def launch(runner, world, cwd, *args, extra=None, inherited="/stale/overlay.yml", check=True):
	start = time.monotonic()
	proc = subprocess.run(
		runner.command(world, cwd, args),
		cwd=str(cwd),
		env=environment(world, runner, extra, inherited),
		capture_output=True,
		text=True,
		timeout=30,
		check=check,
	)
	return proc, time.monotonic() - start


def run(runner, world, cwd, *args, **kw):
	proc, _ = launch(runner, world, cwd, *args, **kw)
	argv, envline = proc.stdout.splitlines()
	return argv, envline


def overlay_args(world, bank):
	return f"argv: [--config] [{world['overlays'] / f'{bank}.yml'}]"


def test_workspaces_get_their_overlay_via_config_flag_and_no_env(runner, world):
	home = world["home"]
	argv, env = run(runner, world, home / "work/beta-site/web", "-p", "a b")
	assert argv == overlay_args(world, "beta") + " [-p] [a b]"
	assert env == "env:unset"
	argv, env = run(runner, world, home / "work/alpha-app/ui")
	assert (argv, env) == (overlay_args(world, "alpha"), "env:unset")
	argv, env = run(runner, world, home / "work/tools")  # a second root of the same bank
	assert (argv, env) == (overlay_args(world, "alpha"), "env:unset")
	argv, env = run(runner, world, home / "work/beta-site", inherited=None)
	assert (argv, env) == (overlay_args(world, "beta"), "env:unset")


def test_outside_workspaces_get_nothing(runner, world):
	home = world["home"]
	for cwd in (home / "work/other", home / "work", home, Path("/")):
		assert run(runner, world, cwd, "x") == ("argv: [x]", "env:/stale/overlay.yml")


def test_missing_overlay_or_routes_fails_safe(runner, world):
	(world["overlays"] / "beta.yml").unlink()
	assert run(runner, world, world["home"] / "work/beta-site") == ("argv:", "env:/stale/overlay.yml")
	world["routes"].unlink()
	assert run(runner, world, world["home"] / "work/alpha-app") == ("argv:", "env:/stale/overlay.yml")


def test_config_subcommand_gets_env_only(runner, world):
	cwd = world["home"] / "work/beta-site/web"
	argv, env = run(runner, world, cwd, "config", "get", "memory.backend")
	assert argv == "argv: [config] [get] [memory.backend]"
	assert env == f"env:{world['overlays'] / 'beta.yml'}"
	assert run(runner, world, world["home"] / "work/other", "config", "list") == (
		"argv: [config] [list]",
		"env:/stale/overlay.yml",
	)


def test_case_variant_root_and_cwd(runner, world):
	world["routes"].write_text("beta\t~/Work/Beta-Site\nalpha\t~/work/alpha-app\n")
	assert run(runner, world, world["home"] / "work/beta-site/web")[0] == overlay_args(world, "beta")
	variant = world["home"] / "WORK/Alpha-App/UI"
	if not variant.is_dir():
		pytest.skip("case-sensitive filesystem")
	assert run(runner, world, variant)[0] == overlay_args(world, "alpha")


def test_symlinks_route_by_target(runner, world, tmp_path):
	home = world["home"]
	inside = home / "work/alpha-app/beta-link"
	inside.symlink_to(home / "work/beta-site/web")
	assert run(runner, world, inside)[0] == overlay_args(world, "beta")
	outside = tmp_path / "outside"
	outside.symlink_to(home / "work/alpha-app")
	assert run(runner, world, outside)[0] == overlay_args(world, "alpha")
	escape = home / "work/beta-site/out-link"
	escape.symlink_to(home / "work/other")
	assert run(runner, world, escape) == ("argv:", "env:/stale/overlay.yml")


def test_longest_root_comments_blank_lines_and_no_trailing_newline(runner, world):
	home = world["home"]
	(home / "work/alpha-app/inner/x").mkdir(parents=True)
	world["routes"].write_text(
		"# header\n\nalpha\t~/work/alpha-app\n../bad\t~/work/other\nrelative\twork/other\n"
		"beta\t~/work/alpha-app/inner"
	)
	assert run(runner, world, home / "work/alpha-app/inner/x")[0] == overlay_args(world, "beta")
	assert run(runner, world, home / "work/alpha-app/ui")[0] == overlay_args(world, "alpha")
	assert run(runner, world, home / "work/other") == ("argv:", "env:/stale/overlay.yml")


def test_roots_with_spaces_and_absolute_roots(runner, world, tmp_path):
	spaced = world["home"] / "my work/proj one"
	spaced.mkdir(parents=True)
	absolute = tmp_path / "abs root" / "deep"
	absolute.mkdir(parents=True)
	(world["overlays"] / "gamma.yml").write_text("memory:\n  backend: hindsight\n")
	world["routes"].write_text(f"alpha\t~/my work/proj one\ngamma\t{tmp_path / 'abs root'}\n")
	assert run(runner, world, spaced)[0] == overlay_args(world, "alpha")
	assert run(runner, world, absolute)[0] == overlay_args(world, "gamma")


def test_many_banks(runner, world):
	lines = []
	for i in range(8):
		(world["home"] / f"many/{i}/sub").mkdir(parents=True)
		(world["overlays"] / f"bank{i}.yml").write_text("memory:\n  backend: hindsight\n")
		lines.append(f"bank{i}\t~/many/{i}\n")
	world["routes"].write_text("".join(lines))
	for i in (0, 3, 7):
		assert run(runner, world, world["home"] / f"many/{i}/sub")[0] == overlay_args(world, f"bank{i}")
	assert run(runner, world, world["home"] / "many") == ("argv:", "env:/stale/overlay.yml")


def test_hooks_and_python_routing_agree(runner, world, tmp_path):
	home = world["home"]
	(tmp_path / "lnk").symlink_to(home / "work/beta-site")
	cases = [
		home / "work/beta-site/web",
		home / "work/alpha-app/ui",
		home / "work/tools",
		home / "work/other",
		home / "work",
		tmp_path / "lnk",
	]
	banks = parse_config(BANKS_JSON, tmp_path / "banks.json").routes
	for cwd in cases:
		bank = routing.bank_for_path(cwd, banks, home)
		expected = overlay_args(world, bank) if bank else "argv:"
		assert run(runner, world, cwd)[0] == expected, cwd


# --- the shim only ---------------------------------------------------------------------------------------------


def test_shim_skips_itself_and_finds_the_real_omp(world):
	shim = next(r for r in RUNNERS if r.name == "shim")
	assert run(shim, world, world["home"] / "work/other", "-v") == ("argv: [-v]", "env:/stale/overlay.yml")


def test_shim_honours_an_explicit_real_omp(world, tmp_path):
	other = tmp_path / "elsewhere" / "omp"
	other.parent.mkdir()
	other.write_text(FAKE_OMP.replace("argv:", "other-argv:"))
	other.chmod(0o755)
	shim = next(r for r in RUNNERS if r.name == "shim")
	argv, _ = run(
		shim, world, world["home"] / "work/other", extra={"OMP_HINDSIGHT_GUARD_REAL_OMP": str(other)}
	)
	assert argv == "other-argv:"


def test_shim_without_a_real_omp_fails_clearly(world):
	shim = next(r for r in RUNNERS if r.name == "shim")
	(world["bin"] / "omp").unlink()
	proc, _ = launch(shim, world, world["home"], check=False)
	assert proc.returncode == 127 and "no real omp found" in proc.stderr


# --- fallback to local memory when the shared memory does not answer -----------------------------------------


class Health(http.server.BaseHTTPRequestHandler):
	status = 200
	delay = 0.0
	hits: list = []  # noqa: RUF012

	def log_message(self, *args):
		pass

	def do_GET(self):
		type(self).hits.append(self.path)
		time.sleep(type(self).delay)
		self.send_response(type(self).status)
		self.send_header("Content-Length", "0")
		self.end_headers()


@pytest.fixture
def server():
	Health.status, Health.delay, Health.hits = 200, 0.0, []
	srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Health)
	srv.daemon_threads = True
	threading.Thread(target=srv.serve_forever, daemon=True).start()
	yield f"http://127.0.0.1:{srv.server_address[1]}"
	srv.shutdown()


def with_url(world, url):
	for bank in ("alpha", "beta"):
		(world["overlays"] / f"{bank}.yml").write_text(
			f'memory:\n  backend: hindsight\nhindsight:\n  apiUrl: {url}\n  apiToken: "not-a-real-key"\n'
		)


def probe(runner, world, cwd, *args, extra=None):
	proc, elapsed = launch(runner, world, cwd, *args, extra=extra)
	return proc.stdout.splitlines()[0], proc.stderr, elapsed


def state_files(world):
	return sorted((world["home"] / ".local/state/omp-hindsight-guard").glob("reach-*"))


def test_up_applies_overlay_and_caches(runner, world, server):
	with_url(world, server)
	cwd = world["home"] / "work/beta-site/web"
	argv, err, _ = probe(runner, world, cwd)
	assert argv == overlay_args(world, "beta") and err == ""
	assert Health.hits == ["/health/ready"]
	argv, _, _ = probe(runner, world, cwd, "config", "get", "memory.backend")  # cached: no second probe
	assert argv == "argv: [config] [get] [memory.backend]" and len(Health.hits) == 1
	state = world["home"] / ".local/state/omp-hindsight-guard"
	assert oct(state.stat().st_mode & 0o777) == "0o700"
	(cache,) = state_files(world)
	assert oct(cache.stat().st_mode & 0o777) == "0o600"
	stamp, word = cache.read_text().split()
	assert stamp.isdigit() and word == "up" and "not-a-real-key" not in cache.read_text()


def test_down_falls_back_to_local_with_one_notice(runner, world, server):
	Health.status = 503
	with_url(world, server)
	argv, err, _ = probe(runner, world, world["home"] / "work/alpha-app/ui", "x")
	assert argv == "argv: [x]"
	assert err == degraded("shared memory (alpha) unreachable")
	argv, err, _ = probe(
		runner, world, world["home"] / "work/tools", "x", extra={"OMP_HINDSIGHT_GUARD_QUIET": "1"}
	)
	assert argv == "argv: [x]" and err == ""
	assert len(Health.hits) == 1  # the failure is cached too


def test_refused_connection_falls_back(runner, world):
	sock = socket.socket()
	sock.bind(("127.0.0.1", 0))
	port = sock.getsockname()[1]
	sock.close()
	with_url(world, f"http://127.0.0.1:{port}")
	argv, err, elapsed = probe(runner, world, world["home"] / "work/beta-site")
	assert argv == "argv:" and "unreachable" in err and elapsed < 2.5


def test_slow_server_times_out_fast(runner, world, server):
	Health.delay = 4.0
	with_url(world, server)
	argv, err, elapsed = probe(runner, world, world["home"] / "work/beta-site")
	assert argv == "argv:" and "unreachable" in err
	assert elapsed < 3.5


def test_cache_expiry_switches_back(runner, world, server):
	Health.status = 503
	with_url(world, server)
	cwd = world["home"] / "work/beta-site"
	assert probe(runner, world, cwd)[0] == "argv:"
	Health.status = 200
	assert probe(runner, world, cwd)[0] == "argv:"  # down cached for 10 s
	assert len(Health.hits) == 1
	argv, err, _ = probe(runner, world, cwd, extra={"OMP_HINDSIGHT_GUARD_PROBE_DOWN_TTL": "0"})
	assert argv == overlay_args(world, "beta") and err == "" and len(Health.hits) == 2
	Health.status = 503
	assert probe(runner, world, cwd)[0] == overlay_args(world, "beta")  # up cached for 30 s
	assert probe(runner, world, cwd, extra={"OMP_HINDSIGHT_GUARD_PROBE_UP_TTL": "0"})[0] == "argv:"


def test_outside_workspaces_never_probe(runner, world, server):
	with_url(world, server)
	assert probe(runner, world, world["home"] / "work/other", "x")[0] == "argv: [x]"
	assert Health.hits == [] and state_files(world) == []


def test_bad_cache_file_is_ignored(runner, world, server):
	with_url(world, server)
	state = world["home"] / ".local/state/omp-hindsight-guard"
	state.mkdir(parents=True)
	cache = state / ("reach-" + "".join(c if c.isalnum() else "_" for c in server))
	cache.write_text("garbage down\n")
	assert probe(runner, world, world["home"] / "work/beta-site")[0] == overlay_args(world, "beta")
	assert len(Health.hits) == 1


def test_roots_with_shell_metacharacters(runner, world):
	odd = world["home"] / 'wei\'rd "q" $HOME `x` [a]* ?'
	(odd / "sub").mkdir(parents=True)
	world["routes"].write_text(f"alpha\t{odd}\n")
	assert run(runner, world, odd / "sub")[0] == overlay_args(world, "alpha")
	assert run(runner, world, world["home"] / "work/other") == ("argv:", "env:/stale/overlay.yml")
	# A glob character in a root must not widen the match.
	world["routes"].write_text("alpha\t~/work/*\n")
	assert run(runner, world, world["home"] / "work/other") == ("argv:", "env:/stale/overlay.yml")


def test_default_overlay_dir_follows_the_config_dir_and_xdg(runner, world, tmp_path):
	cfg = tmp_path / "cfgdir"
	(cfg).mkdir()
	world["overlays"].rename(cfg / "overlays")
	cwd = world["home"] / "work/beta-site"
	unset = {"OMP_HINDSIGHT_GUARD_OVERLAY_DIR": None}
	proc, _ = launch(runner, world, cwd, extra={**unset, "OMP_HINDSIGHT_GUARD_CONFIG_DIR": str(cfg)})
	assert proc.stdout.splitlines()[0] == f"argv: [--config] [{cfg / 'overlays' / 'beta.yml'}]"
	xdg = tmp_path / "xdg"
	(xdg / "omp-hindsight-guard").mkdir(parents=True)
	(cfg / "overlays").rename(xdg / "omp-hindsight-guard" / "overlays")
	proc, _ = launch(runner, world, cwd, extra={**unset, "XDG_CONFIG_HOME": str(xdg)})
	assert (
		proc.stdout.splitlines()[0]
		== f"argv: [--config] [{xdg / 'omp-hindsight-guard' / 'overlays' / 'beta.yml'}]"
	)
	proc, _ = launch(runner, world, cwd, extra=unset)  # nothing under the scratch HOME's default location
	assert proc.stdout.splitlines()[0] == "argv:"


def test_a_users_own_pi_config_files_survives_when_no_overlay_applies(runner, world):
	"""M4: PI_CONFIG_FILES is removed only when an overlay is passed; otherwise omp runs unchanged."""
	mine = "/home/me/own-overlay.yml"
	cwd_outside = world["home"] / "work/other"
	assert run(runner, world, cwd_outside, "x", inherited=mine) == ("argv: [x]", f"env:{mine}")
	assert run(runner, world, cwd_outside, "config", "list", inherited=mine) == (
		"argv: [config] [list]",
		f"env:{mine}",
	)
	# A bank matches but its overlay is missing: still unchanged.
	(world["overlays"] / "beta.yml").unlink()
	assert run(runner, world, world["home"] / "work/beta-site", inherited=mine) == ("argv:", f"env:{mine}")
	# The proxy is down: unchanged as well.
	with_url(world, "http://127.0.0.1:9")
	assert run(runner, world, world["home"] / "work/alpha-app", inherited=mine) == ("argv:", f"env:{mine}")
	# With an overlay the inherited value is removed, as before.
	with_url(world, "http://127.0.0.1:9")
	(world["overlays"] / "alpha.yml").write_text("memory:\n  backend: hindsight\n")
	assert run(runner, world, world["home"] / "work/alpha-app", inherited=mine) == (
		overlay_args(world, "alpha"),
		"env:unset",
	)


def test_a_matching_bank_without_an_overlay_says_so_once_on_stderr(runner, world):
	"""L12(f): silent local memory after a missing overlay was a trap."""
	(world["overlays"] / "beta.yml").unlink()
	proc, _ = launch(runner, world, world["home"] / "work/beta-site")
	assert proc.stderr == degraded("no overlay for bank beta (run omp-hindsight-guard overlays)")
	proc, _ = launch(
		runner, world, world["home"] / "work/beta-site", extra={"OMP_HINDSIGHT_GUARD_QUIET": "1"}
	)
	assert proc.stderr == ""
	proc, _ = launch(runner, world, world["home"] / "work/other")
	assert proc.stderr == ""


def test_the_probe_reads_a_quoted_api_url(runner, world, server):
	with_url(world, f'"{server}"')
	assert probe(runner, world, world["home"] / "work/beta-site")[0] == overlay_args(world, "beta")
	assert Health.hits == ["/health/ready"]


# --- second review: finding 1 (the fallback does not enforce local memory) and 7 (ambiguous roots) -------------------


def degraded(reason):
	return (
		f"omp: {reason}; running with omp's existing configuration (its memory destination is not enforced; "
		"OMP_HINDSIGHT_GUARD_ON_DOWN=block refuses to start instead)\n"
	)


def test_f1_the_notice_does_not_promise_local_memory(runner, world):
	with_url(world, "http://127.0.0.1:9")
	proc, _ = launch(runner, world, world["home"] / "work/beta-site")
	assert "local memory" not in proc.stderr and "not enforced" in proc.stderr


BLOCK = {"OMP_HINDSIGHT_GUARD_ON_DOWN": "block"}


def test_f1_block_mode_refuses_to_start_when_the_proxy_is_down(runner, world):
	with_url(world, "http://127.0.0.1:9")
	proc, _ = launch(runner, world, world["home"] / "work/beta-site", extra=BLOCK, check=False)
	assert proc.returncode == 75 and proc.stdout == ""  # the fake omp never ran
	assert proc.stderr == (
		"omp: shared memory (beta) unreachable; refusing to start (OMP_HINDSIGHT_GUARD_ON_DOWN=block)\n"
	)
	# QUIET silences the notice of the permissive mode only, never a refusal.
	proc, _ = launch(
		runner,
		world,
		world["home"] / "work/beta-site",
		extra={**BLOCK, "OMP_HINDSIGHT_GUARD_QUIET": "1"},
		check=False,
	)
	assert proc.returncode == 75 and "refusing to start" in proc.stderr


def test_f1_block_mode_refuses_when_the_overlay_is_missing(runner, world):
	(world["overlays"] / "beta.yml").unlink()
	proc, _ = launch(runner, world, world["home"] / "work/beta-site", extra=BLOCK, check=False)
	assert proc.returncode == 75 and proc.stdout == "" and "no overlay for bank beta" in proc.stderr


def test_f1_block_mode_leaves_other_folders_and_a_healthy_proxy_alone(runner, world, server):
	assert run(runner, world, world["home"] / "work/other", extra=BLOCK) == (
		"argv:",
		"env:/stale/overlay.yml",
	)
	with_url(world, server)
	argv, _ = run(runner, world, world["home"] / "work/beta-site", extra=BLOCK)
	assert argv == overlay_args(world, "beta")


def test_f7_two_banks_with_equally_long_roots_select_nothing(runner, world):
	(world["overlays"] / "gamma.yml").write_text("memory:\n  backend: hindsight\n")
	world["routes"].write_text("alpha\t~/work/tools\ngamma\t~/work/../work/tools\n")
	proc, _ = launch(runner, world, world["home"] / "work/tools")
	assert proc.stdout.splitlines()[0] == "argv:"  # no overlay for either bank
	assert proc.stderr == degraded("this folder matches more than one bank (alpha, gamma)")
	proc, _ = launch(runner, world, world["home"] / "work/tools", extra=BLOCK, check=False)
	assert proc.returncode == 75 and proc.stdout == ""
	# The same bank twice is not ambiguous, and a longer root still wins.
	world["routes"].write_text("alpha\t~/work/tools\nalpha\t~/work/../work/tools\nbeta\t~/work/tools/sub\n")
	(world["home"] / "work/tools/sub").mkdir()
	assert run(runner, world, world["home"] / "work/tools")[0] == overlay_args(world, "alpha")
	assert run(runner, world, world["home"] / "work/tools/sub")[0] == overlay_args(world, "beta")
