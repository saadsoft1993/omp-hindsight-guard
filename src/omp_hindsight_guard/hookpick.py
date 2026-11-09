"""`omp-hindsight-guard-pick`: the one place that decides which overlay (if any) a launch of omp gets.

The shell functions and the PATH shim are thin: they call this helper from the directory omp is started in and act on
its answer. Everything that needs care lives here, once, in Python: the routing table is parsed strictly, the working
directory is the process's own (`os.getcwd()`, exact bytes), folders are compared by the same `routing.route` the
importer uses, every file and directory consulted must pass `trustwalk` (lstat walk, ACLs), the health probe has its own
timeout and a cache kept through a validated directory descriptor.

Output: the overlay path on stdout (empty: omp runs unchanged). Notices go to stderr. Exit status 75: refuse to start
(`OMP_HINDSIGHT_GUARD_ON_DOWN=block`). Any other status means the helper itself failed.
"""

from __future__ import annotations

import os
import re
import stat
import sys
import time
from pathlib import Path

from omp_hindsight_guard import routing
from omp_hindsight_guard.trustwalk import TrustError, check_path

NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*")
URL_RE = re.compile(r'^\s+apiUrl:\s*"?([^"\s]+)')
TRUST_HINT = "every directory above it must be yours or root's and not writable by group or other, with no ACL granting others access"
EXIT_REFUSE = 75


class Refuse(Exception):
	pass


def env(name: str, default: str) -> str:
	value = os.environ.get(name, "")
	return value if value else default


def block() -> bool:
	return os.environ.get("OMP_HINDSIGHT_GUARD_ON_DOWN", "") == "block"


def degraded(reason: str) -> None:
	"""omp may run anyway, with whatever configuration it already has (its memory destination is NOT enforced), or,
	in block mode, must not start."""
	if block():
		print(f"omp: {reason}; refusing to start (OMP_HINDSIGHT_GUARD_ON_DOWN=block)", file=sys.stderr)
		raise Refuse
	if not os.environ.get("OMP_HINDSIGHT_GUARD_QUIET"):
		print(
			f"omp: {reason}; running with omp's existing configuration (its memory destination is not enforced; "
			"OMP_HINDSIGHT_GUARD_ON_DOWN=block refuses to start instead)",
			file=sys.stderr,
		)


def parse_routes(data: bytes) -> tuple[list[tuple[str, str]], bool]:
	"""(entries, malformed). Exactly one tab per entry; no control character anywhere in a root; absolute roots
	only (`~/` is expanded from HOME). Comments (`#`) and empty lines are skipped; anything else that is not a
	valid entry marks the table malformed, and a table that cannot be decoded is entirely malformed."""
	try:
		text = data.decode("utf-8")
	except UnicodeDecodeError:
		return [], True
	entries: list[tuple[str, str]] = []
	bad = False
	home = os.environ.get("HOME", "")
	for line in text.split("\n"):
		if line == "" or line.startswith("#"):
			continue
		if line.count("\t") != 1:
			bad = True
			continue
		name, root = line.split("\t")
		if (
			not name
			or not root
			or not NAME_RE.fullmatch(name)
			or any(ord(c) < 32 or ord(c) == 127 for c in root)
		):
			bad = True
			continue
		if root.startswith("~/"):
			root = home + "/" + root[2:]
		if not root.startswith("/"):
			bad = True
			continue
		entries.append((name, root))
	return entries, bad


def trusted(path: Path | str, what: str, *, secret: bool = False) -> str | None:
	"""None when trusted, else the notice text."""
	try:
		check_path(path, secret=secret)
	except (TrustError, OSError) as err:
		return f"{what} is not in a trusted location ({err}; {TRUST_HINT})"
	return None


def read_routes(routes: Path) -> tuple[list[tuple[str, str]], str | None, str | None]:
	"""(entries, unknown reason for block mode, problem to announce)."""
	if not routes.exists():
		return [], f"routing table {routes} is missing or unreadable (run omp-hindsight-guard overlays)", None
	problem = trusted(routes, f"routing table {routes}")
	if problem:
		return [], None, problem
	try:
		fd = os.open(routes, os.O_RDONLY | os.O_NONBLOCK)
		with os.fdopen(fd, "rb") as fh:
			if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
				raise OSError("not a regular file")
			data = fh.read()
	except OSError:
		return [], f"routing table {routes} is missing or unreadable (run omp-hindsight-guard overlays)", None
	entries, bad = parse_routes(data)
	unknown = None
	if not entries:
		unknown = f"routing table {routes} has no valid entry"
	if bad:
		unknown = f"routing table {routes} has a malformed entry (run omp-hindsight-guard overlays)"
	return entries, unknown, None


def api_url(overlay: Path) -> str | None:
	try:
		with open(overlay, encoding="utf-8", errors="replace") as fh:
			for line in fh:
				match = URL_RE.match(line.rstrip("\n"))
				if match:
					return match.group(1).rstrip("/")
	except OSError:
		return None
	return None


def _state_dir() -> str:
	home_state = env("XDG_STATE_HOME", os.path.join(os.environ.get("HOME", ""), ".local", "state"))
	return env("OMP_HINDSIGHT_GUARD_STATE_DIR", os.path.join(home_state, "omp-hindsight-guard"))


def open_state_dir() -> int | None:
	"""A descriptor for the state directory, only when it is trusted (created 0700 if missing), else None."""
	path = _state_dir()
	if os.path.islink(path):  # the directory itself is never a symlink (what it points at could be anything)
		return None
	try:
		if not os.path.lexists(path):
			os.makedirs(path, mode=0o700, exist_ok=True)
		check_path(path)
		fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
	except (OSError, TrustError):
		return None
	info = os.fstat(fd)
	if info.st_uid != os.getuid() or info.st_mode & 0o022:
		os.close(fd)
		return None
	return fd


def probe(url: str) -> bool:
	"""GET <url>/health/ready, no key, no proxy, no redirect: up only on exactly 200."""
	import urllib.error  # imported only when a probe is needed: a cache hit starts faster without them
	import urllib.request

	opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
	req = urllib.request.Request(f"{url}/health/ready", method="GET")
	try:
		timeout = float(env("OMP_HINDSIGHT_GUARD_PROBE_TIMEOUT", "1.5"))
	except ValueError:
		timeout = 1.5
	try:
		with opener.open(req, timeout=timeout) as resp:
			return resp.status == 200
	except (urllib.error.URLError, OSError, ValueError):
		return False


def shared_up(url: str) -> bool:
	name = "reach-" + re.sub(r"[^A-Za-z0-9]", "_", url)
	now = int(time.time())
	try:
		up_ttl = int(env("OMP_HINDSIGHT_GUARD_PROBE_UP_TTL", "30"))
		down_ttl = int(env("OMP_HINDSIGHT_GUARD_PROBE_DOWN_TTL", "10"))
	except ValueError:
		up_ttl, down_ttl = 30, 10
	dirfd = open_state_dir()
	try:
		if dirfd is not None:
			try:
				fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dirfd)
				with os.fdopen(fd, "r") as fh:
					info = os.fstat(fh.fileno())
					if stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o022:
						parts = fh.read(64).split()
						if len(parts) >= 2 and parts[0].isdigit():
							age = now - int(parts[0])
							if parts[1] == "up" and age < up_ttl:
								return True
							if parts[1] == "down" and age < down_ttl:
								return False
			except OSError:
				pass
		state = probe(url)
		if dirfd is not None:
			temp = f".{name}.{os.getpid()}.{time.monotonic_ns()}"
			try:
				fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dirfd)
				with os.fdopen(fd, "w") as fh:
					fh.write(f"{now} {'up' if state else 'down'}\n")
				os.rename(temp, name, src_dir_fd=dirfd, dst_dir_fd=dirfd)
			except OSError:
				try:
					os.unlink(temp, dir_fd=dirfd)
				except OSError:
					pass
		return state
	finally:
		if dirfd is not None:
			os.close(dirfd)


def decide() -> str:
	"""The overlay path to use, or '' to run omp unchanged. Raises Refuse."""
	home = os.environ.get("HOME", "")
	cfg = env(
		"OMP_HINDSIGHT_GUARD_CONFIG_DIR",
		os.path.join(env("XDG_CONFIG_HOME", os.path.join(home, ".config")), "omp-hindsight-guard"),
	)
	overlays = Path(env("OMP_HINDSIGHT_GUARD_OVERLAY_DIR", os.path.join(cfg, "overlays")))
	routes = Path(env("OMP_HINDSIGHT_GUARD_ROUTES", str(overlays / "routes.tsv")))
	entries, unknown, problem = read_routes(routes)
	if problem:
		degraded(problem)
		return ""
	if unknown and block():
		degraded(unknown)
	bank = None
	try:
		found = routing.route(os.getcwd(), entries, home)
	except OSError:
		return ""
	if found.ambiguous:
		degraded(f"this folder matches more than one bank ({', '.join(found.candidates[:2])})")
		return ""
	bank = found.bank
	if bank is None:
		return ""
	overlay = overlays / f"{bank}.yml"
	if not overlay.exists() or not os.access(overlay, os.R_OK):
		degraded(f"no overlay for bank {bank} (run omp-hindsight-guard overlays)")
		return ""
	problem = trusted(overlay, f"overlay for bank {bank}")
	if problem:
		degraded(problem)
		return ""
	url = api_url(overlay)
	if url is None:
		# No apiUrl to probe: harmless normally, but under block the overlay cannot be trusted to name a server.
		if block():
			degraded(f"overlay {overlay} names no apiUrl")
		return str(overlay)
	if not shared_up(url):
		degraded(f"shared memory ({bank}) unreachable")
		return ""
	return str(overlay)


def main(argv: list[str] | None = None) -> int:
	try:
		overlay = decide()
	except Refuse:
		return EXIT_REFUSE
	sys.stdout.write(overlay)
	return 0


if __name__ == "__main__":
	sys.exit(main())
