import json
import socket
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from omp_hindsight_guard import proxy, redact

UPSTREAM_KEY = "u" * 64
# Five banks, each with its own key; most tests use the first two.
KEYS = {
	name: char * 64
	for name, char in zip(("alpha", "beta", "gamma", "delta", "epsilon"), "abcde", strict=True)
}
A_KEY = KEYS["alpha"]
B_KEY = KEYS["beta"]
AWS = "AKIA" + "Q3EXAMPLE7KZ2M4P"
# An assignment the redactor must catch, built from neutral-named parts so scanners stay quiet.
PAYLOAD_VALUE = "abc123def456" + "ghi"
ASSIGNMENT = f"API_KEY={PAYLOAD_VALUE}"


class FakeHindsight(BaseHTTPRequestHandler):
	protocol_version = "HTTP/1.1"
	seen: list = []  # noqa: RUF012

	def log_message(self, *args):
		pass

	def _handle(self):
		length = int(self.headers.get("Content-Length") or 0)
		body = self.rfile.read(length) if length else b""
		FakeHindsight.seen.append((self.command, self.path, self.headers.get("Authorization"), body))
		data = json.dumps({"ok": True, "path": self.path}).encode()
		self.send_response(200)
		self.send_header("Content-Type", "application/json")
		self.send_header("Content-Length", str(len(data)))
		self.end_headers()
		self.wfile.write(data)

	do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _handle


def _start(server):
	threading.Thread(target=server.serve_forever, daemon=True).start()
	return server


@pytest.fixture
def stack():
	FakeHindsight.seen = []
	upstream = _start(ThreadingHTTPServer(("127.0.0.1", 0), FakeHindsight))
	config = proxy.Config(
		f"http://127.0.0.1:{upstream.server_address[1]}",
		UPSTREAM_KEY,
		dict(KEYS),
		0,
	)
	server = _start(proxy.serve(config))
	base = f"http://127.0.0.1:{server.server_address[1]}"
	yield base, upstream
	server.shutdown()
	upstream.shutdown()


_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def call(url, method="GET", key=None, body=None, ctype="application/json"):
	headers = {"Authorization": f"Bearer {key}"} if key else {}
	data = None
	if body is not None:
		data = body if isinstance(body, bytes) else json.dumps(body).encode()
		headers["Content-Type"] = ctype
	req = urllib.request.Request(url, data=data, method=method, headers=headers)
	try:
		with _opener.open(req, timeout=10) as r:
			return r.status, r.read()
	except urllib.error.HTTPError as e:
		return e.code, e.read()


def test_health_needs_no_key(stack):
	base, _ = stack
	assert call(f"{base}/health/ready") == (200, b'{"status": "ok"}')
	assert FakeHindsight.seen[-1][2] is None


def test_no_or_wrong_key_is_401(stack):
	base, _ = stack
	assert call(f"{base}/v1/default/banks/alpha/memories/list")[0] == 401
	assert call(f"{base}/v1/default/banks/alpha/memories/list", key="nope")[0] == 401
	assert call(f"{base}/v1/default/banks/alpha/memories/list", key=UPSTREAM_KEY)[0] == 401
	assert FakeHindsight.seen == []


@pytest.mark.parametrize(
	"path",
	[
		"/v1/default/banks/beta/memories/list",
		"/v1/default/banks",
		"/docs",
		"/openapi.json",
		"/metrics",
		"/version",
		"/mcp",
		"/v1/default/banks/alpha/../beta/memories",
		"/v1/default/banks/alpha%2F..%2Fbeta/memories",
	],
)
def test_key_is_pinned_to_its_bank(stack, path):
	base, _ = stack
	assert call(f"{base}{path}", key=A_KEY)[0] in (400, 404)
	assert FakeHindsight.seen == []


def test_forwards_with_upstream_key_and_query(stack):
	base, _ = stack
	status, data = call(f"{base}/v1/default/banks/beta/operations?status=failed&limit=1", key=B_KEY)
	assert status == 200 and json.loads(data)["path"].endswith("?status=failed&limit=1")
	assert FakeHindsight.seen[-1][2] == f"Bearer {UPSTREAM_KEY}"


def test_retain_body_is_redacted_before_upstream(stack):
	base, _ = stack
	body = {
		"async": True,
		"items": [
			{
				"content": f"user: my key is {AWS} and {ASSIGNMENT}\nassistant: noted",
				"document_id": "session-1",
				"tags": ["project:demo"],
				"metadata": {"session_id": "s1"},
			}
		],
	}
	status, _ = call(f"{base}/v1/default/banks/alpha/memories", "POST", A_KEY, body)
	assert status == 200
	sent = FakeHindsight.seen[-1][3].decode()
	assert AWS not in sent and PAYLOAD_VALUE not in sent
	assert "[REDACTED:aws-access-key]" in sent and "[REDACTED:env-assignment]" in sent
	forwarded = json.loads(sent)
	assert forwarded["items"][0]["document_id"] == "session-1"
	assert forwarded["items"][0]["tags"] == ["project:demo"]
	assert forwarded["async"] is True


def test_proxy_keys_are_redacted(stack):
	base, _ = stack
	call(f"{base}/v1/default/banks/alpha/memories/recall", "POST", A_KEY, {"query": f"why {B_KEY}"})
	assert B_KEY not in FakeHindsight.seen[-1][3].decode()


def test_non_json_write_is_refused(stack):
	base, _ = stack
	assert (
		call(f"{base}/v1/default/banks/alpha/memories", "POST", A_KEY, b"raw " + AWS.encode(), "text/plain")[
			0
		]
		== 415
	)
	assert call(f"{base}/v1/default/banks/alpha/memories", "POST", A_KEY, b"{not json")[0] == 400
	assert FakeHindsight.seen == []


def test_body_too_large(stack, monkeypatch):
	base, _ = stack
	monkeypatch.setattr(proxy, "MAX_BODY", 10)
	assert call(f"{base}/v1/default/banks/alpha/memories", "POST", A_KEY, {"items": ["x" * 50]})[0] == 413


def test_upstream_down_is_502():
	config = proxy.Config("http://127.0.0.1:9", UPSTREAM_KEY, {"alpha": A_KEY}, 0)
	server = _start(proxy.serve(config))
	base = f"http://127.0.0.1:{server.server_address[1]}"
	try:
		assert call(f"{base}/health/ready") == (502, b'{"status": "unavailable"}')
		assert call(f"{base}/v1/default/banks/alpha/memories/list", key=A_KEY)[0] == 502
	finally:
		server.shutdown()


def test_config_validation_and_key_lookup():
	config = proxy.Config("http://127.0.0.1:8890", UPSTREAM_KEY, {"alpha": A_KEY, "beta": B_KEY})
	assert config.bank_keys == {"alpha": A_KEY, "beta": B_KEY}
	assert config.port == 8888 and config.upstream_port == 8890 and config.host == "127.0.0.1"
	assert config.bank_for(f"Bearer {B_KEY}") == "beta"
	assert config.bank_for(f"bearer {A_KEY}") == "alpha"
	assert config.bank_for("Bearer ") is None and config.bank_for(None) is None
	assert config.bank_for(f"Basic {A_KEY}") is None and config.bank_for(f"Bearer {UPSTREAM_KEY}") is None
	with pytest.raises(ValueError):
		proxy.Config("http://example.com:8890", UPSTREAM_KEY, {"alpha": A_KEY})
	with pytest.raises(ValueError):
		proxy.Config("https://127.0.0.1:8890", UPSTREAM_KEY, {"alpha": A_KEY})
	with pytest.raises(ValueError):
		proxy.Config("http://127.0.0.1:8890", "", {"alpha": A_KEY})
	assert proxy.Config("http://[::1]:8890", UPSTREAM_KEY, {"alpha": A_KEY}).upstream_host == "::1"


@pytest.mark.parametrize("bank", list(KEYS))
def test_every_bank_key_reaches_only_its_own_bank(stack, bank):
	base, _ = stack
	key = KEYS[bank]
	assert call(f"{base}/v1/default/banks/{bank}/memories/list", key=key)[0] == 200
	assert FakeHindsight.seen[-1][1] == f"/v1/default/banks/{bank}/memories/list"
	seen = len(FakeHindsight.seen)
	for other in KEYS:
		if other != bank:
			assert call(f"{base}/v1/default/banks/{other}/memories/list", key=key)[0] == 404
			assert call(f"{base}/v1/default/banks/{other}/memories", "POST", key, {"items": []})[0] == 404
	assert call(f"{base}/v1/default/banks/{bank}/memories/list", key=UPSTREAM_KEY)[0] == 401
	assert len(FakeHindsight.seen) == seen  # nothing crossed to the upstream


def test_a_new_bank_needs_no_code_change():
	extra = {f"bank-{i}": f"{i:02d}" * 32 for i in range(12)}
	config = proxy.Config("http://127.0.0.1:9", UPSTREAM_KEY, extra, 0)
	assert sorted(config.bank_keys) == sorted(extra)
	assert all(config.bank_for(f"Bearer {key}") == name for name, key in extra.items())


def logged(capsys, *needles, timeout=5.0):
	"""Captured output once every needle appears. The server thread logs after it has sent the response, so the
	client can return first; wait for the line instead of racing it."""
	seen = ""
	deadline = time.monotonic() + timeout
	while time.monotonic() < deadline:
		seen += capsys.readouterr().out
		if all(n in seen for n in needles):
			break
		time.sleep(0.02)
	return seen


def test_log_lines_carry_no_secrets_or_bodies(stack, capsys):
	base, _ = stack
	call(f"{base}/v1/default/banks/alpha/memories", "POST", A_KEY, {"items": [{"content": f"k {AWS}"}]})
	out = logged(capsys, "bank=alpha route=memories status=200 redactions=1")
	assert "bank=alpha route=memories status=200 redactions=1" in out
	assert AWS not in out and A_KEY not in out and UPSTREAM_KEY not in out
	call(f"{base}/v1/default/banks/alpha/memories/recall", "POST", A_KEY, {"query": f"q {AWS}"})
	call(f"{base}/v1/default/banks/alpha/operations/0b1c2d3e-0000-4000-8000-000000000000", key=A_KEY)
	out = logged(capsys, "route=memories/recall status=200 redactions=1", "route=operations/{id} status=200")
	assert "route=memories/recall status=200 redactions=1" in out
	assert "route=operations/{id} status=200" in out and "0b1c2d3e" not in out


B = "/v1/default/banks/alpha"
MM = "mm-1:x@y.z"


@pytest.mark.parametrize(
	("method", "path", "body"),
	[
		("POST", "/memories", {"items": [{"content": "hi"}]}),
		("POST", "/memories/recall", {"query": "q"}),
		("POST", "/reflect", {"query": "q"}),
		("GET", "/memories/list?type=world&q=a%2Fb&consolidation_state=done&limit=5&offset=0", None),
		("GET", "/documents?limit=1", None),
		("GET", "/documents/session-1", None),
		("GET", "/mental-models?detail=content&limit=50&offset=0", None),
		("GET", f"/mental-models/{MM}?detail=content", None),
		("GET", f"/mental-models/{MM}/history", None),
		("POST", "/mental-models", {"name": "n", "source_query": "q", "id": "mm-1"}),
		("POST", f"/mental-models/{MM}/refresh", None),
		("GET", "/operations?status=failed&type=retain&exclude_parents=true", None),
		("GET", "/operations/0b1c2d3e-0000-4000-8000-000000000000", None),
		("PUT", "", {"reflect_mission": "r", "retain_mission": "s"}),
	],
)
def test_allowed_routes_forward(stack, method, path, body):
	base, _ = stack
	assert call(f"{base}{B}{path}", method, A_KEY, body)[0] == 200
	m, fwd, auth, _ = FakeHindsight.seen[-1]
	assert m == method and auth == f"Bearer {UPSTREAM_KEY}"
	assert fwd.split("?")[0] == B + path.split("?")[0]


def test_encoded_id_is_unquoted_once(stack):
	base, _ = stack
	assert call(f"{base}{B}/documents/a%41b", key=A_KEY)[0] == 200
	assert FakeHindsight.seen[-1][1] == f"{B}/documents/aAb"
	assert call(f"{base}{B}/documents/a%7Eb", key=A_KEY)[0] == 400
	assert call(f"{base}{B}/documents/a%2541", key=A_KEY)[0] == 400


@pytest.mark.parametrize(
	("method", "path", "body"),
	[
		("DELETE", "/documents/session-1", None),
		("PATCH", "/documents/session-1", {"tags": ["x"]}),
		("DELETE", f"/mental-models/{MM}", None),
		("DELETE", "", None),
		("GET", "", None),
		("POST", "", {"x": 1}),
		("GET", "/config", None),
		("PATCH", "/config", {"x": 1}),
		("GET", "/webhooks", None),
		("POST", "/directives", {"x": 1}),
		("GET", "/profile", None),
		("POST", "/memories/list", {"x": 1}),
		("GET", "/memories", None),
		("POST", "/documents/session-1", {"x": 1}),
	],
)
def test_denied_routes_404(stack, method, path, body):
	base, _ = stack
	assert call(f"{base}{B}{path}", method, A_KEY, body)[0] == 404
	assert FakeHindsight.seen == []


def test_put_bank_with_other_keys_refused(stack):
	base, _ = stack
	assert call(f"{base}{B}", "PUT", A_KEY, {"reflect_mission": "r", "disposition": {}})[0] == 400
	assert call(f"{base}{B}", "PUT", A_KEY, ["reflect_mission"])[0] == 400
	assert call(f"{base}{B}", "PUT", A_KEY)[0] == 400
	assert FakeHindsight.seen == []


def raw_request(base, target, method="GET", key=A_KEY):
	port = int(base.rsplit(":", 1)[1])
	with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
		s.sendall(
			f"{method} {target} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {key}\r\n"
			"Content-Length: 0\r\n\r\n".encode()
		)
		return int(s.recv(4096).split(b" ", 2)[1])


@pytest.mark.parametrize(
	"target",
	[
		f"{B}/documents/%2e%2e",
		f"{B}/documents/%2E%2E%2Fx",
		f"{B}/documents/a%2fb",
		f"{B}/documents/a%5cb",
		f"//host{B}/memories/list",
		f"{B}//memories/list",
		f"{B}/memories/list;x=1",
		f"{B}/documents/a\\b",
		f"{B}/documents/..",
		"/v1/default/banks/alp%68a/memories/list",
		f"http://evil{B}/memories/list",
		f"{B}/documents/a%zz",
	],
)
def test_path_tricks_never_reach_upstream(stack, target):
	base, _ = stack
	assert raw_request(base, target) in (400, 404)
	assert FakeHindsight.seen == []


def test_query_rules(stack):
	base, _ = stack
	assert call(f"{base}{B}/memories/recall?x=1", "POST", A_KEY, {"query": "q"})[0] == 400
	assert call(f"{base}{B}?a=1", "PUT", A_KEY, {"reflect_mission": "r"})[0] == 400
	assert call(f"{base}{B}/documents?detail=x", key=A_KEY)[0] == 400
	assert call(f"{base}{B}/documents?limit=" + "1" * 201, key=A_KEY)[0] == 400
	assert FakeHindsight.seen == []
	assert call(f"{base}{B}/memories/list?q=a+b%26c&limit=2", key=A_KEY)[0] == 200
	assert FakeHindsight.seen[-1][1] == f"{B}/memories/list?q=a+b%26c&limit=2"


def test_depth_bomb_and_surrogates(stack):
	base, _ = stack
	bomb = b"[" * 100000 + b"]" * 100000
	assert call(f"{base}{B}/memories/recall", "POST", A_KEY, bomb)[0] == 400
	assert FakeHindsight.seen == []
	status, _ = call(f"{base}{B}/memories/recall", "POST", A_KEY, b'{"query": "a\\ud800b"}')
	assert status in (200, 400)
	if status == 200:
		assert b"\\ud800" in FakeHindsight.seen[-1][3]


def test_reject_body_and_too_large(stack, monkeypatch):
	base, _ = stack
	bad = {"items": [{"content": "x", "document_id": "bad\nid"}]}
	assert call(f"{base}{B}/memories", "POST", A_KEY, bad)[0] == 400
	monkeypatch.setattr(redact, "MAX_TEXT_CHARS", 100)
	assert call(f"{base}{B}/memories/recall", "POST", A_KEY, {"query": "x" * 200})[0] == 413
	assert FakeHindsight.seen == []


def test_unexpected_error_is_500_not_forwarded(stack, monkeypatch):
	base, _ = stack

	def boom(*a, **k):
		raise KeyError("x")

	monkeypatch.setattr(proxy, "redact_json", boom)
	assert call(f"{base}{B}/memories/recall", "POST", A_KEY, {"query": "q"})[0] == 500
	assert FakeHindsight.seen == []


def test_error_responses_close_connection(stack):
	base, _ = stack
	req = urllib.request.Request(f"{base}{B}/config", headers={"Authorization": f"Bearer {A_KEY}"})
	try:
		_opener.open(req, timeout=10)
	except urllib.error.HTTPError as e:
		assert e.code == 404 and e.headers.get("Connection") == "close"


def test_key_rules():
	up = "http://127.0.0.1:8890"
	with pytest.raises(ValueError):
		proxy.Config(up, UPSTREAM_KEY, {"alpha": A_KEY, "beta": A_KEY})
	with pytest.raises(ValueError):
		proxy.Config(up, UPSTREAM_KEY, {"": A_KEY})
	with pytest.raises(ValueError):
		proxy.Config(up, UPSTREAM_KEY, {"alpha": "short"})
	with pytest.raises(ValueError):
		proxy.Config(up, A_KEY, {"alpha": A_KEY})
	assert proxy.make_handler(None).timeout == 30


def test_the_importer_can_read_its_documents_and_operations_through_the_proxy(stack):
	"""The importer confirms a retain by reading the operation, and (when the server has pruned it) the document."""
	base, _ = stack
	doc = (
		"mnemopi:alpha:webapp-3tntylzrz3coh:wm:a2"  # default_document_id's shape: colons are plain characters
	)
	assert call(f"{base}{B}/documents/{doc}", key=A_KEY)[0] == 200
	assert FakeHindsight.seen[-1][:2] == ("GET", f"{B}/documents/{doc}")
	op = "550e8400-e29b-41d4-a716-446655440001"
	assert call(f"{base}{B}/operations/{op}", key=A_KEY)[0] == 200
	assert FakeHindsight.seen[-1][:2] == ("GET", f"{B}/operations/{op}")
	# another bank's key cannot read this bank's document or operation
	assert call(f"{base}{B}/documents/{doc}", key=B_KEY)[0] == 404


def test_a_document_id_with_a_space_or_slash_cannot_be_read_back(stack):
	"""Such an id is refused (one path segment, unreserved escapes only); the importer reports it as unconfirmed."""
	base, _ = stack
	before = len(FakeHindsight.seen)
	assert call(f"{base}{B}/documents/a%20b", key=A_KEY)[0] == 400
	assert call(f"{base}{B}/documents/a%2Fb", key=A_KEY)[0] == 400
	assert len(FakeHindsight.seen) == before
