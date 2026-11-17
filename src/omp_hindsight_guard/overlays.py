"""Per-bank omp settings overlays and the route table, generated from banks.json.

Each overlay switches omp to Hindsight with one bank and that bank's proxy key; the shell hooks pick one by
working directory and hand it to omp as `--config <overlay>`. The overlay directory is 0700 and every file in
it 0600. The URL is an argument (default: the proxy's loopback address from banks.json).
"""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
import urllib.parse
from pathlib import Path
from typing import NamedTuple

from omp_hindsight_guard._yaml import require_yaml
from omp_hindsight_guard.config import ROUTES_NAME, Config, Keys, check_ancestor, load_keys, makedirs_private
from omp_hindsight_guard.routing import routes_path, routes_table

MARKER = "# omp settings overlay for the "
# Strings that must stay strings (`null`, `true`, `123`, ...) are written JSON-quoted, which is valid YAML.
TEMPLATE = (
	MARKER
	+ """{bank} bank (written by omp-hindsight-guard).
# Holds a proxy key: keep it 0600 and never commit it.
memory:
  backend: hindsight
hindsight:
  apiUrl: {url}
  apiToken: "{key}"
  bankId: {bank_id}
  scoping: per-project-tagged
  globalScope: false
  recallTimeoutMs: 8000
  requestTimeoutMs: 15000
  retainTimeoutMs: 15000
"""
)
_UNSAFE_URL = re.compile(r"[\x00-\x20\x7f\\]")
_TEMP_NAME = re.compile(r"\.(?:[A-Za-z0-9][A-Za-z0-9_-]*\.yml|routes\.tsv)\.[A-Za-z0-9_]{6,}")


def check_api_url(url: str) -> None:
	"""The proxy key travels in an Authorization header: https anywhere, plain http only to this machine.

	The URL is a base: scheme, host, optional port, optional path. No whitespace or control characters, no
	credentials, query or fragment (an appended path would land inside them and the URL would be echoed with its
	secrets), no malformed port.
	"""
	if _UNSAFE_URL.search(url):
		raise ValueError("hindsight.apiUrl must not contain whitespace, control characters or backslashes")
	parts = urllib.parse.urlsplit(url)
	if "@" in parts.netloc or parts.username is not None or parts.password is not None:
		raise ValueError("hindsight.apiUrl must not contain credentials (user:password@)")
	if "?" in url or "#" in url or parts.query or parts.fragment or ";" in parts.path:
		raise ValueError("hindsight.apiUrl must not contain a query, fragment or path parameters")
	try:
		port = parts.port
	except ValueError:
		raise ValueError("hindsight.apiUrl has an invalid port") from None
	if port == 0 or parts.netloc.endswith(":"):
		raise ValueError("hindsight.apiUrl has an invalid port")
	if parts.scheme == "https" and parts.hostname:
		return
	if parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost", "::1"):
		return
	raise ValueError("hindsight.apiUrl must be https:// or http://127.0.0.1 / http://localhost")


def _write_private(path: Path, text: str) -> None:
	"""Atomic 0600 write: temp file in the same directory, then rename."""
	fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
	try:
		os.fchmod(fd, 0o600)
		with os.fdopen(fd, "w", encoding="utf-8") as fh:
			fh.write(text)
			fh.flush()
			os.fsync(fh.fileno())
		os.replace(tmp, path)
	except BaseException:
		Path(tmp).unlink(missing_ok=True)
		raise


def _generated(path: Path) -> bool:
	"""A regular file this tool wrote: its first line is the marker."""
	if path.is_symlink() or not path.is_file():
		return False
	try:
		with open(path, encoding="utf-8") as fh:
			return fh.readline().startswith(MARKER)
	except (OSError, UnicodeDecodeError):
		return False


def check_overlay_dir(path: Path) -> None:
	"""An existing directory is reused only if it is not a symlink and holds nothing but overlays this tool
	wrote, routes.tsv and its own temporary files. `--out ~` or `--out /tmp` can never have its permissions
	changed, and a `<bank>.yml` of someone else's is never replaced."""
	if path.is_symlink():
		raise ValueError(f"{path} is a symlink; name the overlay directory itself")
	if not path.exists():
		return
	if not path.is_dir():
		raise ValueError(f"{path} exists and is not a directory")
	foreign = [
		p.name
		for p in sorted(path.iterdir())
		if not (
			p.name == ROUTES_NAME
			or _TEMP_NAME.fullmatch(p.name)
			or (p.name.endswith(".yml") and _generated(p))
		)
	]
	if foreign:
		raise ValueError(
			f"{path} holds other files ({foreign[0]}, ...) and is not an overlay directory; "
			"choose a new or empty directory"
		)


def ensure_private_dir(path: Path) -> None:
	check_overlay_dir(path)
	makedirs_private(path)
	os.chmod(path, 0o700)


def write_overlays(config: Config, out: Path, url: str | None = None, keys: Keys | None = None) -> list[Path]:
	"""Write <out>/<bank>.yml for every bank, plus routes.tsv. Returns the paths written."""
	url = (url or config.proxy.local_url).rstrip("/")
	check_api_url(url)
	keys = keys or load_keys(config)
	ensure_private_dir(out)
	written = []
	for bank in config.banks:
		path = out / f"{bank.name}.yml"
		text = TEMPLATE.format(
			bank=bank.name, url=json.dumps(url), key=keys.banks[bank.name], bank_id=json.dumps(bank.name)
		)
		_write_private(path, text)
		written.append(path)
	table = routes_path(out)
	_write_private(table, routes_table(config))
	written.append(table)
	return written


def stale_overlays(config: Config, out: Path) -> list[Path]:
	"""Overlays this tool wrote for banks that are no longer in banks.json."""
	known = {f"{b.name}.yml" for b in config.banks}
	return [p for p in sorted(out.glob("*.yml")) if p.name not in known and _generated(p)]


class Overlay(NamedTuple):
	url: str
	token: str
	bank: str | None


def read_overlay(path: Path) -> Overlay:
	"""URL, token and bank id from ONE validated read: a regular file owned by this user, 0600, not a symlink.
	The caller never reopens the path, so what was validated is what is used."""
	yaml = require_yaml()
	check_ancestor(
		Path(path).parent, f"{path}"
	)  # the directories that decide which file this pathname reaches
	fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
	with os.fdopen(fd) as fh:
		st = os.fstat(fh.fileno())
		if not stat.S_ISREG(st.st_mode):
			raise ValueError(f"{path}: not a regular file")
		if st.st_uid != os.getuid():
			raise ValueError(f"{path}: not owned by the current user")
		if st.st_mode & 0o077:
			raise ValueError(f"{path}: mode {st.st_mode & 0o777:o}, must be 0600")
		text = fh.read()
	try:
		data = yaml.safe_load(text)
	except yaml.YAMLError:
		raise ValueError(f"{path}: not valid YAML") from None
	hindsight = data.get("hindsight") if isinstance(data, dict) else None
	url = hindsight.get("apiUrl") if isinstance(hindsight, dict) else None
	token = hindsight.get("apiToken") if isinstance(hindsight, dict) else None
	if not isinstance(url, str) or not url or not isinstance(token, str) or not token:
		raise ValueError(f"{path}: hindsight.apiUrl and hindsight.apiToken are required")
	try:
		check_api_url(url)
	except ValueError as err:
		raise ValueError(f"{path}: {err}") from None
	bank = hindsight.get("bankId")
	return Overlay(url.rstrip("/"), token, bank if isinstance(bank, str) else None)


def load_overlay(path: Path) -> tuple[str, str]:
	"""`(apiUrl, apiToken)` of an overlay (see read_overlay)."""
	overlay = read_overlay(path)
	return overlay.url, overlay.token


def overlay_bank(path: Path) -> str | None:
	"""hindsight.bankId of an overlay, or None when it has none or the overlay is unusable."""
	try:
		return read_overlay(path).bank
	except (OSError, ValueError):
		return None
