"""Every test runs with a scratch HOME and none of the tool's or XDG variables, so nothing reads or writes the
real user's configuration, keys, state or shell startup files."""

import socket

import pytest


@pytest.fixture(autouse=True)
def scratch_home(tmp_path, monkeypatch):
	home = tmp_path / "scratch-home"
	home.mkdir()
	monkeypatch.setenv("HOME", str(home))
	for name in (
		"XDG_CONFIG_HOME",
		"XDG_STATE_HOME",
		"XDG_DATA_HOME",
		"PI_CONFIG_FILES",
		"OMP_MNEMOPI_ROOT",
		"HINDSIGHT_BANKS",
		"HINDSIGHT_CONF_DIR",
		"HINDSIGHT_BACKUP_DIR",
		"HINDSIGHT_PG_BIN",
	):
		monkeypatch.delenv(name, raising=False)
	import os

	for name in list(os.environ):
		if name.startswith("OMP_HINDSIGHT_GUARD_"):
			monkeypatch.delenv(name)
	return home


def free_port():
	"""A loopback port nothing listens on right now (bound and released; used for 'connection refused')."""
	with socket.socket() as sock:
		sock.bind(("127.0.0.1", 0))
		return sock.getsockname()[1]
