"""Review items L2 (upstream protocol errors) and L3 (strict Content-Length)."""

import socket
import threading

import pytest

from omp_hindsight_guard import proxy
from tests.test_proxy import UPSTREAM_KEY, FakeHindsight, _start

KEY = "k" * 64
BASE = "/v1/default/banks/alpha"


@pytest.fixture
def stack():
	from http.server import ThreadingHTTPServer

	FakeHindsight.seen = []
	upstream = _start(ThreadingHTTPServer(("127.0.0.1", 0), FakeHindsight))
	config = proxy.Config(f"http://127.0.0.1:{upstream.server_address[1]}", UPSTREAM_KEY, {"alpha": KEY}, 0)
	server = _start(proxy.serve(config))
	yield server.server_address[1]
	server.shutdown()
	upstream.shutdown()


def raw(port, head: bytes, body: bytes = b"") -> tuple[int, bytes]:
	with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
		s.sendall(head + b"\r\n\r\n" + body)
		try:
			s.shutdown(socket.SHUT_WR)  # the client sent everything it will send
		except OSError:
			pass  # the server already answered and closed (a refusal does not wait for the rest)
		data = b""
		try:
			while chunk := s.recv(4096):
				data += chunk
		except TimeoutError:
			pass
	status = int(data.split(b" ", 2)[1]) if data.startswith(b"HTTP/") else 0
	return status, data


def post(port, length_headers, body=b'{"q":1}'):
	head = (
		f"POST {BASE}/memories/recall HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {KEY}\r\n"
		"Content-Type: application/json\r\nConnection: close\r\n" + length_headers
	).encode()
	return raw(port, head.rstrip(b"\r\n"), body)


def test_a_plain_content_length_still_works(stack):
	status, _ = post(stack, "Content-Length: 7")
	assert status == 200 and len(FakeHindsight.seen) == 1


@pytest.mark.parametrize(
	"headers",
	[
		"Content-Length: +7",
		"Content-Length: 0x7",
		"Content-Length: 1_0",
		"Content-Length: 7, 7",
		"Content-Length: 7\r\nContent-Length: 7",
		"Content-Length: 7\r\nContent-Length: 8",
		"Content-Length: -7",
		"Content-Length: 99999999999",
		"Content-Length: 7.0",
		"Content-Length: \u0667",
	],
)
def test_odd_content_lengths_are_refused_and_nothing_is_forwarded(stack, headers):
	status, _ = post(stack, headers)
	assert status == 400
	assert FakeHindsight.seen == []


def test_a_bad_upstream_reply_is_a_502_not_a_dropped_connection():
	garbage = socket.socket()
	garbage.bind(("127.0.0.1", 0))
	garbage.listen(5)
	port = garbage.getsockname()[1]
	replies = [
		b"this is not http\r\n\r\n",
		b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nshort",
		b"HTTP/1.1 999\r\n\r\n",
	]

	def serve():
		for reply in replies:
			conn, _ = garbage.accept()
			conn.recv(65536)
			conn.sendall(reply)
			conn.close()

	threading.Thread(target=serve, daemon=True).start()
	config = proxy.Config(f"http://127.0.0.1:{port}", UPSTREAM_KEY, {"alpha": KEY}, 0)
	server = _start(proxy.serve(config))
	try:
		for _ in replies:
			head = f"GET {BASE}/memories/list HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {KEY}\r\nConnection: close".encode()
			status, data = raw(server.server_address[1], head)
			assert status == 502, data
			assert KEY.encode() not in data and UPSTREAM_KEY.encode() not in data
	finally:
		server.shutdown()
		garbage.close()


# --- second review: 17 (framing) and 18 (unauthenticated resource use) -------------------------------------------


def test_f17_a_body_shorter_than_its_content_length_is_not_forwarded(stack):
	status, _ = post(stack, "Content-Length: 50", body=b'{"q":1}')
	assert status == 400 and FakeHindsight.seen == []


@pytest.mark.parametrize(
	("headers", "expected"),
	[
		("Transfer-Encoding: gzip\r\nContent-Length: 7", 501),
		("Transfer-Encoding: identity\r\nContent-Length: 7", 501),
		("Transfer-Encoding: identity\r\nTransfer-Encoding: chunked", 411),
		("Transfer-Encoding: chunked", 411),
		("Transfer-Encoding: x, chunked", 411),
		("Transfer-Encoding:", 501),
	],
)
def test_f17_any_transfer_encoding_is_refused(stack, headers, expected):
	status, _ = post(stack, headers)
	assert status == expected and FakeHindsight.seen == []


def slow_upstream(delay):
	"""A listener that accepts, counts and answers /health/ready only after `delay` seconds."""
	srv = socket.socket()
	srv.bind(("127.0.0.1", 0))
	srv.listen(16)
	hits = []

	def serve():
		while True:
			try:
				conn, _ = srv.accept()
			except OSError:
				return
			hits.append(1)

			def answer(c=conn):
				try:
					c.recv(65536)
					threading.Event().wait(delay)
					c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
				except OSError:
					pass
				finally:
					c.close()

			threading.Thread(target=answer, daemon=True).start()

	threading.Thread(target=serve, daemon=True).start()
	return srv, hits


def health(port):
	head = b"GET /health/ready HTTP/1.1\r\nHost: x\r\nConnection: close"
	return raw(port, head)


def test_f18_health_has_its_own_short_timeout(monkeypatch):
	import time

	srv, _ = slow_upstream(4)
	monkeypatch.setattr(proxy, "HEALTH_TIMEOUT_S", 0.5)
	config = proxy.Config(f"http://127.0.0.1:{srv.getsockname()[1]}", UPSTREAM_KEY, {"alpha": KEY}, 0)
	server = _start(proxy.serve(config))
	try:
		start = time.monotonic()
		status, _ = health(server.server_address[1])
		assert status == 502 and time.monotonic() - start < 2.5
	finally:
		server.shutdown()
		srv.close()


def test_f18_health_probes_are_coalesced_and_cached(monkeypatch):
	srv, hits = slow_upstream(0)
	monkeypatch.setattr(proxy, "HEALTH_CACHE_S", 30)
	config = proxy.Config(f"http://127.0.0.1:{srv.getsockname()[1]}", UPSTREAM_KEY, {"alpha": KEY}, 0)
	server = _start(proxy.serve(config))
	try:
		results = []
		workers = [
			threading.Thread(target=lambda: results.append(health(server.server_address[1])[0]))
			for _ in range(8)
		]
		for w in workers:
			w.start()
		for w in workers:
			w.join()
		assert results == [200] * 8 and len(hits) == 1
	finally:
		server.shutdown()
		srv.close()


def test_f18_an_upstream_reply_larger_than_the_limit_is_a_502(stack, monkeypatch):
	monkeypatch.setattr(proxy, "MAX_UPSTREAM", 5)
	head = f"GET {BASE}/memories/list HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {KEY}\r\nConnection: close".encode()
	status, data = raw(stack, head)
	assert status == 502 and b"ok" not in data.split(b"\r\n\r\n", 1)[1]


def test_f18_connections_are_bounded(monkeypatch):
	from http.server import ThreadingHTTPServer

	monkeypatch.setattr(proxy, "MAX_CONNECTIONS", 2)
	upstream = _start(ThreadingHTTPServer(("127.0.0.1", 0), FakeHindsight))
	config = proxy.Config(f"http://127.0.0.1:{upstream.server_address[1]}", UPSTREAM_KEY, {"alpha": KEY}, 0)
	server = _start(proxy.serve(config))
	port = server.server_address[1]
	idle = [socket.create_connection(("127.0.0.1", port), timeout=10) for _ in range(2)]
	import time

	def until(want):
		status = None
		for _ in range(100):  # the two handler threads need a moment to start; a busy machine needs more
			status = health(port)[0]
			if status == want:
				return status
			time.sleep(0.1)
		return status

	try:
		assert until(503) == 503
	finally:
		for s in idle:
			s.close()
	assert until(200) == 200  # a slot was freed
	server.shutdown()
	upstream.shutdown()


# --- third review, R14: a health check is parsed by the same framing rules as every other request -----------------


def health_with(port, headers: bytes, body: bytes = b"", close=True):
	head = (
		b"GET /health/ready HTTP/1.1\r\nHost: x\r\n" + (b"Connection: close\r\n" if close else b"") + headers
	)
	return raw(port, head.rstrip(b"\r\n"), body)


def test_r14_a_clean_health_check_still_answers(stack):
	assert health_with(stack, b"")[0] == 200
	assert health_with(stack, b"Content-Length: 0")[0] == 200


@pytest.mark.parametrize(
	("headers", "body", "status"),
	[
		(b"Content-Length: 5", b"hello", 400),  # a body on a health check
		(b"Content-Length: 5", b"", 400),  # declared, never sent
		(b"Content-Length: 0\r\nContent-Length: 0", b"", 400),  # duplicate lengths
		(b"Content-Length: +0", b"", 400),
		(b"Transfer-Encoding: chunked", b"0\r\n\r\n", 411),
		(b"Transfer-Encoding: gzip", b"", 501),
	],
)
def test_r14_health_framing_is_validated_before_anything_is_answered(stack, headers, body, status):
	got, _ = health_with(stack, headers, body)
	assert got == status


def test_r14_a_smuggled_request_in_a_health_body_is_never_parsed_as_the_next_request(stack):
	"""Keep-alive: the unread body of a health check used to be taken as the start of the next request."""
	smuggled = f"GET {BASE}/memories/list HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {KEY}\r\n\r\n".encode()
	head = b"GET /health/ready HTTP/1.1\r\nHost: x\r\nContent-Length: %d" % len(smuggled)
	with socket.create_connection(("127.0.0.1", stack), timeout=10) as s:
		s.sendall(head + b"\r\n\r\n" + smuggled)
		data = b""
		while chunk := s.recv(4096):
			data += chunk
	assert data.count(b"HTTP/1.1 ") == 1 and data.startswith(b"HTTP/1.1 400")  # one answer, then closed
	assert FakeHindsight.seen == []  # the smuggled request never reached the upstream
