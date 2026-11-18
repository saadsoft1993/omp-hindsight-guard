"""The one JSON configuration (`banks.json`) and where the tool keeps its files.

Everything is off until it is configured: there is no built-in bank, root, key or URL. The file holds paths to
key files, never keys. Unknown fields are rejected so a typo cannot silently weaken a setting.

    {
      "version": 1,
      "proxy": {
        "listen_host": "127.0.0.1",
        "listen_port": 8888,
        "upstream_url": "http://127.0.0.1:8890",
        "upstream_key_file": "keys/upstream.key"
      },
      "banks": {
        "work": {"key_file": "keys/work.key", "roots": ["~/code/work"]},
        "home": {"key_file": "keys/home.key", "roots": ["~/code/home", "~/notes"]}
      },
      "import": {"mnemopi_root": null, "exclude_labels": [], "allow_link_prefixes": []}
    }

Relative paths are relative to the directory holding banks.json. A root is `~/...` or an absolute path.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import json
import os
import re
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from omp_hindsight_guard.pathrules import ROUTES_NAME, ascii_lower, canonical  # noqa: F401  (re-exported)
from omp_hindsight_guard.trustwalk import TrustError, check_path

APP = "omp-hindsight-guard"
ENV_CONFIG_DIR = "OMP_HINDSIGHT_GUARD_CONFIG_DIR"
ENV_OVERLAY_DIR = "OMP_HINDSIGHT_GUARD_OVERLAY_DIR"
ENV_STATE_DIR = "OMP_HINDSIGHT_GUARD_STATE_DIR"
CONFIG_NAME = "banks.json"
SCHEMA_VERSION = 1

MIN_KEY_LEN = 32
MAX_KEY_LEN = 512
# Printable ASCII without space, double quote and backslash: a key can be written into a YAML overlay and an
# Authorization header verbatim, with nothing to escape.
KEY_RE = re.compile(r"[!#-\[\]-~]+")
BANK_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
_HOSTNAME = re.compile(r"[A-Za-z0-9.\-]{1,253}")
_BAD_ROOT = re.compile(r"[\x00-\x1f\x7f]")

DEFAULT_PORT = 8888
DEFAULT_UPSTREAM = "http://127.0.0.1:8890"


class ConfigError(ValueError):
	"""The configuration or a key file is unusable; the message says what to fix and never contains a key."""


def _env(env: Mapping[str, str] | None) -> Mapping[str, str]:
	return os.environ if env is None else env


def _xdg(env: Mapping[str, str], var: str, fallback: str, home: Path) -> Path:
	value = env.get(var)
	return Path(value) if value else home / fallback


def config_dir(env: Mapping[str, str] | None = None, home: Path | None = None) -> Path:
	env, home = _env(env), home or Path.home()
	if env.get(ENV_CONFIG_DIR):
		return Path(env[ENV_CONFIG_DIR]).expanduser()
	return _xdg(env, "XDG_CONFIG_HOME", ".config", home) / APP


def overlay_dir(env: Mapping[str, str] | None = None, home: Path | None = None) -> Path:
	env = _env(env)
	if env.get(ENV_OVERLAY_DIR):
		return Path(env[ENV_OVERLAY_DIR]).expanduser()
	return config_dir(env, home) / "overlays"


def state_dir(env: Mapping[str, str] | None = None, home: Path | None = None) -> Path:
	env, home = _env(env), home or Path.home()
	if env.get(ENV_STATE_DIR):
		return Path(env[ENV_STATE_DIR]).expanduser()
	return _xdg(env, "XDG_STATE_HOME", ".local/state", home) / APP


def default_config_path(env: Mapping[str, str] | None = None) -> Path:
	return config_dir(env) / CONFIG_NAME


@dataclasses.dataclass(frozen=True)
class Bank:
	name: str
	key_file: Path
	roots: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class ProxySettings:
	listen_host: str
	listen_port: int
	upstream_url: str
	upstream_key_file: Path | None
	allow_remote_listen: bool

	@property
	def local_url(self) -> str:
		"""Where a client on this machine reaches the proxy."""
		host = "127.0.0.1" if self.listen_host in ("0.0.0.0", "::", "") else self.listen_host
		host = f"[{host}]" if ":" in host else host
		return f"http://{host}:{self.listen_port}"


@dataclasses.dataclass(frozen=True)
class ImportSettings:
	mnemopi_root: Path | None
	exclude_labels: tuple[str, ...]
	allow_link_prefixes: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class Config:
	path: Path
	proxy: ProxySettings
	banks: tuple[Bank, ...]
	importer: ImportSettings

	def bank(self, name: str) -> Bank:
		for bank in self.banks:
			if bank.name == name:
				return bank
		raise ConfigError(f"no bank named {name!r} in {self.path}")

	@property
	def routes(self) -> list[tuple[str, str]]:
		"""`(bank, root)` for every root of every bank, in file order."""
		return [(bank.name, root) for bank in self.banks for root in bank.roots]


class _Duplicate(ValueError):
	pass


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
	out: dict[str, Any] = {}
	for key, value in pairs:
		if key in out:
			raise _Duplicate(key)
		out[key] = value
	return out


def _obj(value: Any, where: str, allowed: set[str], required: set[str] = frozenset()) -> dict[str, Any]:
	if not isinstance(value, dict):
		raise ConfigError(f"{where}: expected an object")
	unknown = sorted(set(value) - allowed)
	if unknown:
		raise ConfigError(f"{where}: unknown field {unknown[0]!r} (allowed: {', '.join(sorted(allowed))})")
	missing = sorted(required - set(value))
	if missing:
		raise ConfigError(f"{where}: missing field {missing[0]!r}")
	return value


def _text(value: Any, where: str) -> str:
	if not isinstance(value, str) or not value.strip():
		raise ConfigError(f"{where}: expected a non-empty string")
	return value


def _string_list(value: Any, where: str) -> tuple[str, ...]:
	if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
		raise ConfigError(f"{where}: expected a list of non-empty strings")
	return tuple(value)


def resolve_path(value: str, base: Path) -> Path:
	path = Path(value).expanduser()
	return path if path.is_absolute() else base / path


def normalize_root(root: str, where: str) -> str:
	"""A bank root: `~/...` or an absolute path, plain ASCII, no control characters, no `.`, `..` or empty
	components, never `~` or `/` alone. The shell launchers resolve a root with their own shell, and only a
	spelling that every launcher (and routing.py) reduces to the same directory can be allowed: `..` through a
	folder that does not exist, or a non-ASCII name that each shell lower-cases differently, would not be."""
	if _BAD_ROOT.search(root):
		raise ConfigError(f"{where}: control characters are not allowed in a root")
	trimmed = root.rstrip("/") if root not in ("/",) else root
	if trimmed in ("", "/", "~"):
		raise ConfigError(f"{where}: {root!r} is too broad; name a project folder")
	if not (trimmed.startswith("~/") or trimmed.startswith("/")):
		raise ConfigError(f"{where}: {root!r} must start with ~/ or be an absolute path")
	if not root.isascii():
		raise ConfigError(
			f"{where}: {root!r} must be ASCII (the shells fold non-ASCII case differently); use a symlink"
		)
	rest = trimmed[2:] if trimmed.startswith("~/") else trimmed[1:]
	if any(part in ("", ".", "..") for part in rest.split("/")):
		raise ConfigError(
			f"{where}: {root!r} must not contain '.', '..' or empty components; write the real path"
		)
	return trimmed


def check_listen_host(host: str, allow_remote: bool, where: str) -> None:
	if host in LOOPBACK_HOSTS:
		return
	if not allow_remote:
		raise ConfigError(
			f"{where}: {host!r} is not a loopback address; the proxy listens on loopback only unless "
			"allow_remote_listen is true (and then it must sit behind a TLS terminator)"
		)
	try:
		ipaddress.ip_address(host)
	except ValueError:
		if not _HOSTNAME.fullmatch(host):
			raise ConfigError(f"{where}: {host!r} is not an address or host name") from None


def parse_config(data: Any, path: Path) -> Config:
	base = path.parent
	top = _obj(data, "banks.json", {"version", "proxy", "banks", "import"}, {"version", "proxy", "banks"})
	if top["version"] != SCHEMA_VERSION or isinstance(top["version"], bool):
		raise ConfigError(f"banks.json: version must be {SCHEMA_VERSION}")
	raw = _obj(
		top["proxy"],
		"proxy",
		{"listen_host", "listen_port", "upstream_url", "upstream_key_file", "allow_remote_listen"},
		set(),
	)
	port = raw.get("listen_port", DEFAULT_PORT)
	if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
		raise ConfigError("proxy.listen_port: expected a port number")
	remote = raw.get("allow_remote_listen", False)
	if not isinstance(remote, bool):
		raise ConfigError("proxy.allow_remote_listen: expected true or false")
	host = _text(raw.get("listen_host", "127.0.0.1"), "proxy.listen_host")
	check_listen_host(host, remote, "proxy.listen_host")
	proxy = ProxySettings(
		host,
		port,
		_text(raw.get("upstream_url", DEFAULT_UPSTREAM), "proxy.upstream_url"),
		resolve_path(_text(raw["upstream_key_file"], "proxy.upstream_key_file"), base)
		if "upstream_key_file" in raw
		else None,
		remote,
	)
	banks_raw = top["banks"]
	if not isinstance(banks_raw, dict) or not banks_raw:
		raise ConfigError("banks: expected an object with at least one bank")
	banks: list[Bank] = []
	seen_names: set[str] = set()
	seen_roots: dict[str, str] = {}
	for name, value in banks_raw.items():
		if not BANK_RE.fullmatch(name):
			raise ConfigError(
				f"banks.{name}: a bank name is 1-64 letters, digits, '_' or '-' and starts with one"
			)
		if name.casefold() in seen_names:
			raise ConfigError(f"banks.{name}: bank names must differ ignoring case")
		seen_names.add(name.casefold())
		spec = _obj(value, f"banks.{name}", {"key_file", "roots"}, {"key_file"})
		roots = tuple(
			normalize_root(r, f"banks.{name}.roots")
			for r in _string_list(spec.get("roots", []), f"banks.{name}.roots")
		)
		for root in roots:
			# Compared the way routing compares: symlinks and `..` resolved, case folded. A spelling that
			# resolves to `/` or the home directory is as broad as `/` itself.
			canon = canonical_root(root)
			if canon in (canonical("/"), canonical(Path.home())):
				raise ConfigError(
					f"banks.{name}.roots: {root!r} is too broad (it resolves to {canon.rstrip('/') or '/'})"
				)
			if canon in seen_roots and seen_roots[canon] != name:
				raise ConfigError(
					f"banks.{name}.roots: {root} is already a root of bank {seen_roots[canon]} "
					"(the two spellings name the same directory)"
				)
			seen_roots[canon] = name
		banks.append(Bank(name, resolve_path(_text(spec["key_file"], f"banks.{name}.key_file"), base), roots))
	imp = _obj(top.get("import", {}), "import", {"mnemopi_root", "exclude_labels", "allow_link_prefixes"})
	prefixes = _string_list(imp.get("allow_link_prefixes", []), "import.allow_link_prefixes")
	for prefix in prefixes:
		if not prefix.startswith("https://") or len(prefix) <= len("https://") or not prefix.endswith("/"):
			raise ConfigError(
				f"import.allow_link_prefixes: {prefix!r} must be an https:// URL prefix ending in '/'"
			)
	root_value = imp.get("mnemopi_root")
	importer = ImportSettings(
		resolve_path(_text(root_value, "import.mnemopi_root"), base) if root_value is not None else None,
		_string_list(imp.get("exclude_labels", []), "import.exclude_labels"),
		prefixes,
	)
	return Config(path, proxy, tuple(banks), importer)


def load_config(path: Path | str | None = None, env: Mapping[str, str] | None = None) -> Config:
	path = Path(path).expanduser() if path else default_config_path(env)
	try:
		text = _read_trusted_text(path)
	except FileNotFoundError:
		raise ConfigError(
			f"no configuration at {path}; run `omp-hindsight-guard init` or copy banks.example.json"
		)
	except OSError as err:
		raise ConfigError(f"{path}: {err.strerror or type(err).__name__}") from None
	try:
		data = json.loads(text, object_pairs_hook=_no_duplicates)
	except _Duplicate as err:
		raise ConfigError(f"{path}: duplicate field {err.args[0]!r}") from None
	except ValueError as err:
		raise ConfigError(f"{path}: not valid JSON ({err})") from None
	return parse_config(data, path)


def read_key(path: Path, what: str) -> str:
	"""The key in a key file. The file must be a regular file owned by this user and unreadable by others."""
	try:
		with open(path, "rb") as fh:
			info = os.fstat(fh.fileno())
			if not stat.S_ISREG(info.st_mode):
				raise ConfigError(f"{what}: {path} is not a regular file")
			if info.st_uid != os.getuid():
				raise ConfigError(f"{what}: {path} is not owned by the current user")
			if info.st_mode & 0o077:
				raise ConfigError(f"{what}: {path} is readable by group or other; run chmod 600 {path}")
			check_dir_trusted(path.parent, f"{what}: the directory holding the key")
			check_ancestor(
				path, f"{what}", secret=True
			)  # the file itself too: no ACL may let anyone else read it
			raw = fh.read(MAX_KEY_LEN + 64)
	except IsADirectoryError:
		raise ConfigError(f"{what}: {path} is not a regular file") from None
	except FileNotFoundError:
		raise ConfigError(f"{what}: key file {path} does not exist") from None
	except OSError as err:
		raise ConfigError(f"{what}: cannot read {path} ({err.strerror or type(err).__name__})") from None
	try:
		key = raw.decode("ascii").strip()
	except UnicodeDecodeError:
		raise ConfigError(f"{what}: {path} is not ASCII text") from None
	if not KEY_RE.fullmatch(key) or not MIN_KEY_LEN <= len(key) <= MAX_KEY_LEN:
		raise ConfigError(
			f"{what}: {path} must hold one key of {MIN_KEY_LEN}-{MAX_KEY_LEN} printable characters "
			"(no spaces, quotes or backslashes)"
		)
	return key


@dataclasses.dataclass(frozen=True)
class Keys:
	upstream: str
	banks: dict[str, str]


def load_keys(config: Config, banks: tuple[str, ...] | None = None) -> Keys:
	"""Read the upstream key and the bank keys (all banks, or the named ones); every key must be distinct."""
	if config.proxy.upstream_key_file is None:
		raise ConfigError("proxy.upstream_key_file: required to load proxy keys")
	upstream = read_key(config.proxy.upstream_key_file, "proxy.upstream_key_file")
	wanted = [b for b in config.banks if banks is None or b.name in banks]
	keys = {b.name: read_key(b.key_file, f"banks.{b.name}.key_file") for b in wanted}
	every = [upstream, *keys.values()]
	if len(set(every)) != len(every):
		raise ConfigError("every bank and the upstream need their own key; two key files hold the same key")
	return Keys(upstream, keys)


def canonical_root(root: str, home: Path | None = None) -> str:
	"""canonical() of a banks.json root (`~/...` means `home`)."""
	home = home or Path.home()
	return canonical(home / root[2:] if root.startswith("~/") else root)


def check_dir_trusted(path: Path, what: str) -> None:
	"""A directory we read secrets from or write them into: ours, and not writable by group or other (anyone
	who can write into it can replace the files in it)."""
	try:
		info = os.stat(path)
	except OSError as err:
		raise ConfigError(f"{what}: cannot inspect {path} ({err.strerror or type(err).__name__})") from None
	if not stat.S_ISDIR(info.st_mode):
		raise ConfigError(f"{what}: {path} is not a directory")
	if info.st_uid != os.getuid():
		raise ConfigError(f"{what}: the directory {path} is not owned by the current user")
	if info.st_mode & 0o022:
		raise ConfigError(
			f"{what}: the directory {path} is writable by group or other; run chmod go-w {path}"
		)
	check_ancestor(path, what)


def _read_trusted_text(path: Path) -> str:
	"""Read banks.json: a regular file owned by this user, not writable by group or other, in a directory that
	is not writable by group or other (otherwise another user could point the proxy's upstream key anywhere)."""
	with open(path, "rb") as fh:
		info = os.fstat(fh.fileno())
		if not stat.S_ISREG(info.st_mode):
			raise ConfigError(f"{path} is not a regular file")
		if info.st_uid != os.getuid():
			raise ConfigError(f"{path} is not owned by the current user")
		if info.st_mode & 0o022:
			raise ConfigError(f"{path} is writable by group or other; run chmod go-w {path}")
		check_dir_trusted(path.parent, str(path))
		check_ancestor(path, str(path))  # the file itself too: no ACL may let anyone else write it
		return fh.read().decode("utf-8")


def check_ancestor(path: str | Path, what: str, *, secret: bool = False) -> None:
	"""Refuse `path` unless only you (or root) can change what it reaches: see trustwalk.py. Walked lexically with
	lstat, symlinks and `..` followed as the kernel does, ACLs inspected, a group never assumed to be private."""
	try:
		check_path(path, secret=secret)
	except TrustError as err:
		raise ConfigError(f"{what}: {err}") from None


def makedirs_private(path: Path) -> None:
	"""Create path and any missing parents with mode 0700. A directory that already exists is left as it is, but
	only if it is ours and not writable by group or other: it is rejected, not silently reused. When parents have
	to be created, the existing directory they are created in is checked too, and so is any directory another
	process created in the meantime (a racing mkdir is not trusted just because it exists)."""
	missing = []
	probe = path
	while not probe.exists():
		missing.append(probe)
		if probe.parent == probe:
			break
		probe = probe.parent
	if not missing:
		check_dir_trusted(path, "directory")  # the directory itself, and every directory above it
		return
	check_ancestor(probe, "directory")
	for directory in reversed(missing):
		try:
			directory.mkdir(mode=0o700)
		except FileExistsError:
			check_dir_trusted(directory, "directory")  # created by someone else just now
			continue
		os.chmod(directory, 0o700)
