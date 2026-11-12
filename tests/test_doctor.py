import io
import os
import sys
import time

import pytest

from omp_hindsight_guard import doctor, overlays
from omp_hindsight_guard.config import ENV_CONFIG_DIR, load_keys
from tests.conftest import free_port
from tests.helpers import Stack, make_setup

BANKS = {
	"alpha": ["~/work/alpha-app"],
	"beta": ["~/work/beta-site", "~/work/tools"],
	"gamma": ["/srv/gamma"],
	"delta": ["~/work/delta"],
}


@pytest.fixture
def setup(tmp_path, scratch_home):
	for d in ("work/alpha-app", "work/beta-site", "work/tools", "work/delta"):
		(scratch_home / d).mkdir(parents=True)
	cfg_dir = tmp_path / "cfg"
	config = make_setup(cfg_dir, BANKS)
	env = {ENV_CONFIG_DIR: str(cfg_dir)}
	overlays.write_overlays(config, cfg_dir / "overlays")
	return config, env, cfg_dir


@pytest.fixture
def stack(setup):
	config, _, _ = setup
	s = Stack(config)
	yield s
	s.close()


def check(config, env, **kw):
	buf = io.StringIO()
	code = doctor.run_doctor(config.path, env=env, out=buf, **kw)
	return code, buf.getvalue()


def lines(text, level):
	return [line for line in text.splitlines() if line.startswith(f"{level:<4} ")]


def test_a_healthy_setup_passes_every_bank_and_prints_no_key(setup, stack):
	config, env, _ = setup
	code, text = check(config, env, proxy_url=stack.url)
	assert code == 0, text
	assert "0 failure(s)" in text and lines(text, "fail") == []
	for bank in BANKS:
		assert any(f"isolation {bank}" in line for line in lines(text, "ok")), text
		assert any(f"overlay {bank}" in line for line in lines(text, "ok")), text
	keys = load_keys(config)
	for key in (keys.upstream, *keys.banks.values()):
		assert key not in text


def test_isolation_traffic_is_exactly_the_documented_requests(setup, stack):
	config, env, _ = setup
	from tests.helpers import Upstream

	check(config, env, proxy_url=stack.url)
	# Only the own-bank listing per bank reaches the upstream (everything else is refused by the proxy).
	forwarded = [(m, p) for m, p, _, _ in Upstream.seen if p != "/health/ready"]
	assert sorted(forwarded) == sorted(("GET", f"/v1/default/banks/{b}/memories/list") for b in BANKS)
	assert all(auth == f"Bearer {load_keys(config).upstream}" for _, _, auth, _ in Upstream.seen if auth)


def test_a_bank_hindsight_has_not_created_yet_is_a_warning_not_a_failure(setup, stack):
	config, env, _ = setup
	from tests.helpers import Upstream

	# Hindsight creates a bank on its first write, so a freshly configured bank answers 404 to its own key until then.
	Upstream.missing = {"beta"}
	code, text = check(config, env, proxy_url=stack.url)
	assert code == 0, text
	assert lines(text, "fail") == [], text
	assert any("isolation beta" in line and "not created" in line for line in lines(text, "warn")), text
	for bank in ("alpha", "gamma", "delta"):
		assert any(f"isolation {bank}" in line for line in lines(text, "ok")), text


def test_offline_skips_the_proxy(setup):
	config, env, _ = setup
	code, text = check(config, env, offline=True)
	assert code == 0 and "/health/ready" not in text and "isolation" not in text


def test_missing_config_is_exit_2(tmp_path):
	buf = io.StringIO()
	assert doctor.run_doctor(tmp_path / "none.json", env={}, out=buf) == 2
	assert "fail config" in buf.getvalue()


def test_missing_overlay_and_stale_routes_fail(setup):
	config, env, cfg_dir = setup
	(cfg_dir / "overlays" / "gamma.yml").unlink()
	code, text = check(config, env, offline=True)
	assert code == 1 and any("overlay gamma" in line for line in lines(text, "fail"))
	overlays.write_overlays(config, cfg_dir / "overlays")
	(cfg_dir / "overlays" / "routes.tsv").write_text("alpha\t~/elsewhere\n")
	code, text = check(config, env, offline=True)
	assert code == 1 and any("routes.tsv" in line for line in lines(text, "fail"))


def test_a_new_bank_in_banks_json_makes_the_overlays_stale(setup):
	_config, env, cfg_dir = setup
	bigger = make_setup(cfg_dir, {**BANKS, "epsilon": ["~/work/epsilon"]})
	code, text = check(bigger, env, offline=True)
	assert code == 1
	assert any("overlay epsilon" in line for line in lines(text, "fail"))
	assert any("routes.tsv" in line for line in lines(text, "fail"))


def test_overlay_with_the_wrong_token_or_bank_fails(setup):
	config, env, cfg_dir = setup
	path = cfg_dir / "overlays" / "beta.yml"
	path.write_text(path.read_text().replace('bankId: "beta"', 'bankId: "alpha"'))
	path.chmod(0o600)
	code, text = check(config, env, offline=True)
	assert code == 1 and any("bankId does not match" in line for line in lines(text, "fail"))
	overlays.write_overlays(config, cfg_dir / "overlays")
	keys = load_keys(config)
	path.write_text(path.read_text().replace(keys.banks["beta"], "z" * 40))
	path.chmod(0o600)
	code, text = check(config, env, offline=True)
	assert code == 1 and any("token differs" in line for line in lines(text, "fail"))
	assert keys.banks["beta"] not in text and "z" * 40 not in text


def test_loose_key_or_overlay_permissions_fail(setup):
	config, env, cfg_dir = setup
	(cfg_dir / "keys" / "alpha.key").chmod(0o644)
	code, text = check(config, env, offline=True)
	assert code == 1 and any("key files" in line and "chmod 600" in line for line in lines(text, "fail"))
	(cfg_dir / "keys" / "alpha.key").chmod(0o600)
	(cfg_dir / "overlays").chmod(0o755)
	code, text = check(config, env, offline=True)
	assert code == 1 and any("overlay directory mode" in line for line in lines(text, "fail"))


def test_a_proxy_that_is_down_fails(setup):
	config, env, _ = setup
	code, text = check(config, env, proxy_url=f"http://127.0.0.1:{free_port()}")
	assert code == 1 and any("proxy /health/ready" in line for line in lines(text, "fail"))


@pytest.fixture
def default_port_setup(tmp_path, scratch_home, monkeypatch):
	"""A configuration that uses the built-in proxy address, moved to a free port so the test does not depend on 8888."""
	port = free_port()
	monkeypatch.setattr(doctor, "DEFAULT_PROXY_URL", f"http://127.0.0.1:{port}", raising=False)
	cfg_dir = tmp_path / "cfg-default"
	config = make_setup(cfg_dir, {"alpha": ["/srv/alpha"]}, listen_port=port)
	overlays.write_overlays(config, cfg_dir / "overlays")
	return config, {ENV_CONFIG_DIR: str(cfg_dir)}, port


def test_no_proxy_at_the_default_address_is_a_hint_and_not_a_failure(default_port_setup):
	config, env, port = default_port_setup
	code, text = check(config, env)
	assert code == 0, text
	assert lines(text, "fail") == []
	hint = lines(text, "warn")
	assert any(
		f"no proxy answered at http://127.0.0.1:{port}; pass --proxy-url or set it in banks.json" in line
		for line in hint
	), text
	assert "/health/ready" not in text and "0 failure(s)" in text


def test_an_address_given_with_proxy_url_that_refuses_is_still_a_failure(default_port_setup):
	config, env, port = default_port_setup
	code, text = check(config, env, proxy_url=f"http://127.0.0.1:{port}")
	assert code == 1 and any("proxy /health/ready" in line for line in lines(text, "fail")), text
	assert not any("no proxy answered" in line for line in text.splitlines())


def test_a_listener_at_the_default_address_that_answers_badly_is_still_a_failure(default_port_setup):
	import socket
	import threading

	config, env, port = default_port_setup
	server = socket.socket()
	server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	server.bind(("127.0.0.1", port))
	server.listen(1)

	def serve():
		conn, _ = server.accept()
		conn.recv(4096)
		conn.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		conn.close()

	thread = threading.Thread(target=serve, daemon=True)
	thread.start()
	try:
		code, text = check(config, env)
	finally:
		server.close()
		thread.join(5)
	assert code == 1, text
	assert any("answered 503" in line for line in lines(text, "fail")), text
	assert not any("no proxy answered" in line for line in text.splitlines())


def test_an_address_set_in_banks_json_that_refuses_is_still_a_failure(tmp_path, scratch_home):
	# The built-in default stays 8888; this configuration chose another port itself, so nothing listening there is a real failure.
	port = free_port()
	config = make_setup(tmp_path / "cfg-chosen", {"alpha": ["/srv/alpha"]}, listen_port=port)
	code, text = check(config, {ENV_CONFIG_DIR: str(tmp_path / "cfg-chosen")})
	assert code == 1, text
	assert any(f"http://127.0.0.1:{port} answered nothing" in line for line in lines(text, "fail")), text
	assert not any("no proxy answered" in line for line in text.splitlines())


def test_a_proxy_without_one_of_the_banks_fails_that_bank_only(setup):
	config, env, _ = setup
	partial = Stack(config, only_banks=("alpha", "beta", "gamma"))  # delta is not configured in the proxy
	try:
		code, text = check(config, env, proxy_url=partial.url)
	finally:
		partial.close()
	assert code == 1
	failed = lines(text, "fail")
	assert any("isolation delta" in line and "own key on own bank -> 401" in line for line in failed), text
	# The other banks now see delta as an unknown bank (404) and still pass.
	assert any("isolation alpha" in line for line in lines(text, "ok")), text


def test_a_proxy_that_does_not_check_keys_fails_loudly(setup, stack):
	config, env, _ = setup
	# Pointing doctor at the upstream itself (no key check, no bank pinning) must fail every bank.
	code, text = check(config, env, proxy_url=stack.upstream_url)
	assert code == 1
	failed = lines(text, "fail")
	assert len([line for line in failed if "isolation" in line]) == len(BANKS), text
	assert all("expected 401" in line and "expected 404" in line for line in failed if "isolation" in line)


def test_redirects_are_not_followed(setup, stack):
	assert doctor.http_status(stack.url + "/nope") in (401, 404)
	assert doctor.http_status("http://127.0.0.1:1") == 0


def test_backup_freshness(setup, tmp_path):
	config, env, _ = setup
	code, text = check(config, env, offline=True, backup_dir=tmp_path / "none")
	assert code == 1 and any("no hindsight-*.dump" in line for line in lines(text, "fail"))
	backups = tmp_path / "backups"
	backups.mkdir()
	dump = backups / "hindsight-2026-01-01-0000.dump"
	dump.write_text("x")
	code, text = check(config, env, offline=True, backup_dir=backups)
	assert code == 0 and any("backup" in line for line in lines(text, "ok"))
	old = time.time() - 40 * 3600
	os.utime(dump, (old, old))
	code, text = check(config, env, offline=True, backup_dir=backups)
	assert code == 1 and any("40 h old" in line for line in lines(text, "fail"))
	code, _ = check(config, env, offline=True, backup_dir=backups, backup_max_age_hours=48)
	assert code == 0


def test_missing_pyyaml_is_a_failure_not_a_silent_skip(setup, monkeypatch):
	config, env, _ = setup
	monkeypatch.setitem(sys.modules, "yaml", None)
	code, text = check(config, env, offline=True)
	assert code == 1 and any("PyYAML" in line for line in lines(text, "fail"))


def test_roots_that_do_not_exist_only_warn(setup, scratch_home):
	config, env, _ = setup
	(scratch_home / "work/delta").rmdir()
	code, text = check(config, env, offline=True)
	assert code == 0 and any("bank delta root" in line for line in lines(text, "warn"))


def test_world_writable_banks_json_is_refused_by_the_loader_and_reported(setup):
	config, env, _ = setup
	config.path.chmod(0o666)
	buf = io.StringIO()
	assert doctor.run_doctor(config.path, env=env, out=buf, offline=True) == 2
	assert "writable by group or other" in buf.getvalue()
