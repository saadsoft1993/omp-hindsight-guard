"""`omp-hindsight-guard init`: write a first banks.json and the key files it names.

Never overwrites anything: an existing banks.json or key file stops the command or is kept. Keys are random,
created 0600 in a 0700 directory, and never printed.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
from pathlib import Path
from typing import TextIO

from omp_hindsight_guard.config import (
	CONFIG_NAME,
	DEFAULT_PORT,
	DEFAULT_UPSTREAM,
	SCHEMA_VERSION,
	ConfigError,
	makedirs_private,
	parse_config,
)

KEY_BYTES = 48  # token_urlsafe(48) is 64 characters from [A-Za-z0-9_-]


def parse_bank_args(values: list[str]) -> dict[str, list[str]]:
	"""`NAME=ROOT` pairs (repeat a name to give it several roots)."""
	banks: dict[str, list[str]] = {}
	for value in values:
		name, sep, root = value.partition("=")
		if not sep or not name or not root:
			raise ConfigError(f"--bank {value!r}: expected NAME=ROOT, for example work=~/code/work")
		banks.setdefault(name, []).append(root)
	return banks


def create_key(path: Path) -> bool:
	"""Create a random key file (0600). Returns False and leaves the file alone if it already exists."""
	makedirs_private(path.parent)
	try:
		fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
	except FileExistsError:
		return False
	with os.fdopen(fd, "w") as fh:
		fh.write(secrets.token_urlsafe(KEY_BYTES) + "\n")
	os.chmod(path, 0o600)
	return True


def init_config(config_dir: Path, banks: dict[str, list[str]], out: TextIO | None = None) -> int:
	out = out or sys.stdout
	if not banks:
		print(
			"init needs at least one --bank NAME=ROOT, for example --bank work=~/code/work", file=sys.stderr
		)
		return 2
	path = config_dir / CONFIG_NAME
	if path.exists():
		print(f"{path} already exists; edit it by hand (init never overwrites)", file=sys.stderr)
		return 2
	data = {
		"version": SCHEMA_VERSION,
		"proxy": {
			"listen_host": "127.0.0.1",
			"listen_port": DEFAULT_PORT,
			"upstream_url": DEFAULT_UPSTREAM,
			"upstream_key_file": "keys/upstream.key",
		},
		"banks": {
			name: {"key_file": f"keys/bank-{name}.key", "roots": roots} for name, roots in banks.items()
		},
		"import": {"mnemopi_root": None, "exclude_labels": [], "allow_link_prefixes": []},
	}
	try:
		parse_config(data, path)  # the same validation the other commands apply
	except ConfigError as err:
		print(f"not written: {err}", file=sys.stderr)
		return 2
	makedirs_private(config_dir)
	with open(path, "w", encoding="utf-8") as fh:
		json.dump(data, fh, indent=2)
		fh.write("\n")
	os.chmod(path, 0o600)
	print(f"wrote {path}", file=out)
	for rel in ["keys/upstream.key", *(f"keys/bank-{n}.key" for n in banks)]:
		key = config_dir / rel
		print(f"{'created' if create_key(key) else 'kept   '} {key}", file=out)
	print(
		"next: set Hindsight's own API key to the contents of keys/upstream.key (see docs/server-setup.md), "
		"then run `omp-hindsight-guard overlays` and `omp-hindsight-guard proxy`.",
		file=out,
	)
	return 0
