"""Command line: `omp-hindsight-guard <command>`."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from collections.abc import Sequence
from importlib import resources
from pathlib import Path

from omp_hindsight_guard import __version__
from omp_hindsight_guard._yaml import MissingDependency
from omp_hindsight_guard.config import (
	ENV_CONFIG_DIR,
	Config,
	ConfigError,
	config_dir,
	default_config_path,
	load_config,
	load_keys,
	overlay_dir,
)

SCRIPTS = {
	"backup": "backup.sh",
	"canary-count": "canary-count.sh",
	"hsadmin": "hsadmin.sh",
	"outbox-check": "outbox-check.sh",
}


def _load(args: argparse.Namespace) -> Config:
	return load_config(args.config or default_config_path())


def cmd_init(args: argparse.Namespace) -> int:
	from omp_hindsight_guard.init import init_config, parse_bank_args

	directory = args.config.parent if args.config else config_dir()
	return init_config(directory, parse_bank_args(args.bank))


def cmd_proxy(args: argparse.Namespace) -> int:
	from omp_hindsight_guard import proxy

	config = _load(args)
	keys = load_keys(config)
	return proxy.run(proxy.Config.from_settings(config.proxy, keys), config.proxy.allow_remote_listen)


def cmd_overlays(args: argparse.Namespace) -> int:
	from omp_hindsight_guard.overlays import stale_overlays, write_overlays

	config = _load(args)
	out = (args.out or overlay_dir()).expanduser()
	try:
		written = write_overlays(config, out, args.url)
	except ValueError as err:  # a URL that would send the key in the clear
		print(f"omp-hindsight-guard: {err}", file=sys.stderr)
		return 2
	for path in written:
		print(f"wrote {path}")
	for path in stale_overlays(config, out):
		if args.prune:
			path.unlink()
			print(f"removed {path}")
		else:
			print(f"stale overlay (not a bank in banks.json; --prune removes it): {path}")
	return 0


def cmd_route(args: argparse.Namespace) -> int:
	from omp_hindsight_guard.routing import bank_for_path

	bank = bank_for_path(Path(args.path).expanduser(), _load(args).routes)
	print(bank or "-")
	return 0 if bank else 1


def cmd_hook(args: argparse.Namespace) -> int:
	from omp_hindsight_guard.shellhooks import hook_command

	return hook_command(
		args.shell,
		args.config.parent if args.config else config_dir(),
		install=args.install,
		uninstall=args.uninstall,
		rc=args.rc.expanduser() if args.rc else None,
		yes=args.yes,
	)


def cmd_link(args: argparse.Namespace) -> int:
	from omp_hindsight_guard.shellhooks import link_repo, unlink_repo

	overlays = overlay_dir()
	if args.remove:
		return unlink_repo(overlays, args.repo)
	return link_repo(_load(args), overlays, args.repo, args.bank)


def cmd_import(args: argparse.Namespace) -> int:
	from omp_hindsight_guard import importer

	rest = list(args.rest)
	if args.config:
		rest = ["--config", str(args.config), *rest]
	return importer.main(rest)


def cmd_doctor(args: argparse.Namespace) -> int:
	from omp_hindsight_guard.doctor import run_doctor

	return run_doctor(
		args.config,
		proxy_url=args.proxy_url,
		offline=args.offline,
		backup_dir=args.backup_dir,
		backup_max_age_hours=args.backup_max_age_hours,
	)


def cmd_redact(args: argparse.Namespace) -> int:
	from omp_hindsight_guard.redact import RejectBody, redact_text, residual_findings

	text = sys.stdin.read()
	try:
		out, counts = redact_text(text)
	except RejectBody as err:
		print(f"refused: {err}", file=sys.stderr)
		return 2
	sys.stdout.write(out)
	found = residual_findings(out)
	summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none"
	print(f"redactions: {summary}; residual findings: {len(found)}", file=sys.stderr)
	return 1 if args.fail_on_residual and found else 0


def cmd_script(args: argparse.Namespace) -> int:
	script = resources.files("omp_hindsight_guard") / "scripts" / SCRIPTS[args.command]
	env = dict(os.environ)
	env.setdefault(
		"HINDSIGHT_PYTHON", sys.executable
	)  # the scripts need a Python for the backup lock and checks
	# A configuration the operator named, or one that exists in the default place, must load: a broken one is an
	# error, never a silent switch to "no banks". Only a missing default file means "environment settings only".
	config = _load(args) if args.config or default_config_path().exists() else None
	if config is not None:
		env.setdefault("HINDSIGHT_BANKS", " ".join(b.name for b in config.banks))
		if config.importer.mnemopi_root:
			env.setdefault("OMP_MNEMOPI_ROOT", str(config.importer.mnemopi_root))
		env.setdefault(ENV_CONFIG_DIR, str(config.path.parent))
	with resources.as_file(script) as path:
		return subprocess.run(["bash", str(path), *args.rest], env=env, check=False).returncode


def build_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(
		prog="omp-hindsight-guard",
		description="Redacting proxy, per-folder memory banks and importer for a self-run Hindsight server.",
	)
	parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
	parser.add_argument("--config", type=Path, help="banks.json (default: the tool's config directory)")
	sub = parser.add_subparsers(dest="command", required=True, metavar="command")

	p = sub.add_parser("init", help="write a first banks.json and key files")
	p.add_argument(
		"--bank",
		action="append",
		default=[],
		metavar="NAME=ROOT",
		help="a bank and one of its roots (repeatable)",
	)
	p.set_defaults(func=cmd_init)

	p = sub.add_parser("proxy", help="run the redacting proxy")
	p.set_defaults(func=cmd_proxy)

	p = sub.add_parser("overlays", help="write per-bank omp overlays and routes.tsv")
	p.add_argument(
		"--url", help="hindsight.apiUrl the overlays carry (default: the proxy's loopback address)"
	)
	p.add_argument("--out", type=Path, help="overlay directory (default: <config dir>/overlays)")
	p.add_argument("--prune", action="store_true", help="remove overlays for banks no longer in banks.json")
	p.set_defaults(func=cmd_overlays)

	p = sub.add_parser("route", help="print the bank a directory belongs to (- and exit 1 when none)")
	p.add_argument("path", nargs="?", default=".")
	p.set_defaults(func=cmd_route)

	p = sub.add_parser("hook", help="install a shell hook or the PATH shim (opt-in)")
	p.add_argument("shell", choices=("zsh", "bash", "fish", "shim"))
	p.add_argument("--install", action="store_true", help="append the startup line to --rc after showing it")
	p.add_argument("--uninstall", action="store_true", help="remove the lines --install added")
	p.add_argument("--rc", type=Path, help="startup file (default: ~/.zshrc, ~/.bashrc, fish config.fish)")
	p.add_argument("--yes", action="store_true", help="do not ask before appending")
	p.set_defaults(func=cmd_hook)

	p = sub.add_parser("link", help="per-repo mode: link REPO/.omp/config.yml to the bank's overlay")
	p.add_argument("repo", type=Path)
	p.add_argument("--bank", help="bank to use (default: the bank whose root contains the repo)")
	p.add_argument("--remove", action="store_true", help="remove the link instead")
	p.set_defaults(func=cmd_link)

	p = sub.add_parser("import", help="import mnemopi memories (one-time migration); see `import --help`")
	p.set_defaults(func=cmd_import)

	for name in ("doctor", "check"):
		p = sub.add_parser(name, help="check configuration, overlays and per-bank key isolation")
		p.add_argument("--proxy-url", help="proxy to test (default: the loopback address from banks.json)")
		p.add_argument("--offline", action="store_true", help="skip the checks that talk to the proxy")
		p.add_argument("--backup-dir", type=Path, help="also require a recent hindsight-*.dump here")
		p.add_argument("--backup-max-age-hours", type=float, default=26)
		p.set_defaults(func=cmd_doctor)

	p = sub.add_parser("redact", help="redact stdin to stdout (counts on stderr); to try the patterns")
	p.add_argument(
		"--fail-on-residual", action="store_true", help="exit 1 when the residual scan still finds something"
	)
	p.set_defaults(func=cmd_redact)

	for name, script in SCRIPTS.items():
		p = sub.add_parser(name, help=f"run the packaged {script} (see its header for settings)")
		p.set_defaults(func=cmd_script)
	return parser


PASSTHROUGH = ("import", *SCRIPTS)


def split_passthrough(argv: list[str]) -> tuple[list[str], list[str]]:
	"""For `import` and the script commands, everything after the command belongs to that command."""
	i = 0
	while i < len(argv):
		arg = argv[i]
		if arg == "--config":
			i += 2
		elif arg.startswith("--config="):
			i += 1
		elif arg in PASSTHROUGH:
			return argv[: i + 1], argv[i + 1 :]
		else:
			return argv, []
	return argv, []


def main(argv: Sequence[str] | None = None) -> int:
	head, rest = split_passthrough(list(sys.argv[1:] if argv is None else argv))
	args = build_parser().parse_args(head)
	args.rest = rest
	try:
		return args.func(args)
	except ConfigError as err:
		print(f"omp-hindsight-guard: {err}", file=sys.stderr)
		return 2
	except MissingDependency as err:
		print(f"omp-hindsight-guard: {err}", file=sys.stderr)
		return 2


if __name__ == "__main__":
	sys.exit(main())
