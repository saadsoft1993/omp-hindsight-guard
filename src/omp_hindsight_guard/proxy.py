"""Redacting proxy in front of a Hindsight server.

Listens on loopback (default 127.0.0.1:8888) and forwards to an upstream Hindsight on loopback. Expose it to
other machines only through a TLS terminator you control (a reverse proxy, `tailscale serve`, ...); Hindsight
itself stays unexposed. For every request:
- `GET /health/ready` is answered without auth with a fixed body and the upstream status.
- Anything else needs `Authorization: Bearer <client key>`. Each client key maps to exactly one bank (a key
  file per bank in banks.json), compared in constant time; no key or an unknown key -> 401.
- The request target is validated (no traversal, encoded separators, `;`, backslashes or control chars) and
  rebuilt from its parsed parts. Only the method + route pairs in ROUTES, under `/v1/default/banks/<that
  bank>`, are forwarded; everything else -> 404. Query strings are only accepted on GET, with per-route names.
- Write bodies must be JSON; every string in them is redacted (redact.py), identifier fields with token rules
  only. A non-JSON write body -> 415, so nothing unredacted gets through.
- The client key is replaced by Hindsight's own key before forwarding.
Settings come from banks.json; every key file must be unreadable by group and other. Logs carry method, bank,
route class, status and the number of redactions only: never bodies, headers, queries, ids or keys.
"""

import hmac
import http.client
import json
import re
import socket
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

from omp_hindsight_guard.config import MIN_KEY_LEN, Keys, check_listen_host
from omp_hindsight_guard.config import ProxySettings as Settings
from omp_hindsight_guard.redact import RejectBody, TextTooLarge, redact_json

DEFAULT_PORT = 8888
MAX_BODY = 32 * 1024 * 1024
UPSTREAM_TIMEOUT_S = 300  # reflect can run for minutes
HEALTH_TIMEOUT_S = 5  # the unauthenticated probe never waits as long as a real request
HEALTH_CACHE_S = 1.0  # concurrent and repeated probes share one upstream request
MAX_UPSTREAM = 64 * 1024 * 1024  # the most of an upstream reply the proxy will buffer
MAX_CONNECTIONS = 128  # simultaneous client connections; more are answered 503 at once
WRITE_METHODS = {"POST", "PUT"}
MAX_QUERY_VALUE = 200
BANK_PREFIX = ("v1", "default", "banks")
BANK_MISSION_KEYS = {"reflect_mission", "retain_mission"}
_ID = re.compile(r"^[A-Za-z0-9:_.\-@]{1,200}$")
_ESCAPE = re.compile(r"%([0-9A-Fa-f]{2})")
_UNRESERVED = re.compile(r"^[A-Za-z0-9\-._~]$")
_BAD_TARGET = re.compile(r"[\x00-\x1f\x7f\\#\s]")
_BAD_PATH = re.compile(r";|%2f|%5c|%2e|\.\.|//", re.IGNORECASE)
_PAGING = frozenset({"limit", "offset"})
_LENGTH = re.compile(r"[0-9]{1,10}")

# (method, path pattern after the bank, query names allowed). "{id}" matches one validated id segment.
ROUTES = (
	("PUT", (), frozenset()),
	("POST", ("memories",), frozenset()),
	("POST", ("memories", "recall"), frozenset()),
	("POST", ("reflect",), frozenset()),
	("GET", ("memories", "list"), _PAGING | {"type", "q", "consolidation_state"}),
	("GET", ("documents",), _PAGING),
	("GET", ("documents", "{id}"), _PAGING),
	("GET", ("mental-models",), _PAGING | {"detail"}),
	("GET", ("mental-models", "{id}"), _PAGING | {"detail"}),
	("GET", ("mental-models", "{id}", "history"), _PAGING),
	("POST", ("mental-models",), frozenset()),
	("POST", ("mental-models", "{id}", "refresh"), frozenset()),
	("GET", ("operations",), _PAGING | {"status", "type", "exclude_parents"}),
	("GET", ("operations", "{id}"), _PAGING),
)


class BadTarget(ValueError):
	pass


def _segment(raw, allow_escapes):
	"""One path segment, unquoted exactly once. Escapes are only allowed for unreserved chars in ids."""
	if "%" in raw:
		if not allow_escapes or "%" in _ESCAPE.sub("", raw):
			raise BadTarget(raw)
		if any(not _UNRESERVED.match(chr(int(h, 16))) for h in _ESCAPE.findall(raw)):
			raise BadTarget(raw)
	return unquote(raw)


def parse_target(target):
	"""(segments, query pairs) from a raw request target; BadTarget when it is not clean."""
	if not target.startswith("/") or _BAD_TARGET.search(target):
		raise BadTarget(target)
	path, _, query = target.partition("?")
	if _BAD_PATH.search(path):
		raise BadTarget(target)
	raw = path[1:].split("/")
	if raw and raw[-1] == "":
		raw.pop()
	if any(seg == "" for seg in raw):
		raise BadTarget(target)
	pairs = []
	if query:
		try:
			pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True)
		except ValueError as e:
			raise BadTarget(target) from e
	return raw, pairs


def match_route(method, segments):
	"""(route class, decoded ids by position, allowed query names) or None. segments are raw, after the bank."""
	for r_method, pattern, names in ROUTES:
		if r_method != method or len(pattern) != len(segments):
			continue
		decoded = []
		for want, seg in zip(pattern, segments, strict=True):
			if want == "{id}":
				value = _segment(seg, allow_escapes=True)
				if not _ID.match(value):
					raise BadTarget(seg)
				decoded.append(value)
			elif seg == want:
				decoded.append(want)
			else:
				break
		else:
			return "/".join(pattern) or "bank", decoded, names
	return None


class Config:
	def __init__(self, upstream, upstream_key, bank_keys, port=DEFAULT_PORT, host="127.0.0.1"):
		if not upstream_key or not bank_keys or any(not k for k in bank_keys.values()):
			raise ValueError("the proxy needs an upstream key and a key for every bank")
		if any(not bank for bank in bank_keys):
			raise ValueError("empty bank name")
		keys = [upstream_key, *bank_keys.values()]
		if any(len(k) < MIN_KEY_LEN for k in keys):
			raise ValueError(f"proxy keys must be at least {MIN_KEY_LEN} characters")
		if len(set(keys)) != len(keys):
			raise ValueError("every bank (and the upstream) needs its own key")
		parts = urlsplit(upstream)
		if parts.scheme != "http" or parts.hostname not in ("127.0.0.1", "localhost", "::1"):
			raise ValueError("the upstream must be http://127.0.0.1:<port> (or localhost / [::1])")
		self.upstream_host = parts.hostname
		self.upstream_port = parts.port or 80
		self.upstream_key = upstream_key
		self.bank_keys = dict(bank_keys)  # bank -> client key
		self.port = port
		self.host = host
		self.secrets = (upstream_key, *bank_keys.values())
		self.health = None  # (monotonic time, status) of the last health probe
		self.health_lock = threading.Lock()

	@classmethod
	def from_settings(cls, settings: Settings, keys: Keys):
		return cls(
			settings.upstream_url, keys.upstream, keys.banks, settings.listen_port, settings.listen_host
		)

	def bank_for(self, authorization):
		"""The bank this Authorization header's key belongs to, or None. Checks every key (constant time each)."""
		scheme, _, token = (authorization or "").partition(" ")
		token = token.strip() if scheme.lower() == "bearer" else ""
		found = None
		for bank, key in self.bank_keys.items():
			if hmac.compare_digest(token.encode(), key.encode()):
				found = bank
		return found if token else None


def log(method, bank, route, status, redactions):
	stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	print(
		f"{stamp} {method} bank={bank or '-'} route={route} status={status} redactions={redactions}",
		flush=True,
	)


def make_handler(config):
	class Handler(BaseHTTPRequestHandler):
		protocol_version = "HTTP/1.1"
		server_version = "hindsight-proxy"
		sys_version = ""
		timeout = 30

		def log_message(self, *args):  # the default logs the full request line (query strings)
			pass

		def _reply(self, status, body=b"", content_type="application/json", close=False):
			self.send_response(status)
			if body:
				self.send_header("Content-Type", content_type)
			self.send_header("Content-Length", str(len(body)))
			if close:
				self.send_header("Connection", "close")
				self.close_connection = True
			self.end_headers()
			if body and self.command != "HEAD":
				self.wfile.write(body)

		def _error(self, status, message, bank=None, route="-"):
			self._reply(status, json.dumps({"detail": message}).encode(), close=True)
			log(self.command, bank, route, status, 0)

		def _framing(self):
			"""(declared body length, None), or (None, refusing status), from the headers alone: nothing is read."""
			encodings = self.headers.get_all("Transfer-Encoding")
			if encodings is not None:  # any transfer coding at all: not supported, never guessed at
				return None, (411 if any("chunked" in v.lower() for v in encodings) else 501)
			lengths = self.headers.get_all("Content-Length") or []
			if len(lengths) > 1 or (lengths and not _LENGTH.fullmatch(lengths[0])):
				return None, 400  # duplicates and anything but plain ASCII digits (+5, 1_0, 5, 5, 0x5)
			length = int(lengths[0]) if lengths else 0
			if length > MAX_BODY:
				return None, 413
			return length, None

		def _read_body(self):
			length, refused = self._framing()
			if refused:
				return None, refused
			data = self.rfile.read(length) if length else b""
			if len(data) != length:
				return None, 400  # the client closed before sending what it declared: nothing is forwarded
			return data, None

		def _forward(self, method, target, body, headers, timeout=None, limit=None):
			limit = MAX_UPSTREAM if limit is None else limit
			conn = http.client.HTTPConnection(
				config.upstream_host, config.upstream_port, timeout=timeout or UPSTREAM_TIMEOUT_S
			)
			try:
				conn.request(method, target, body=body or None, headers=headers)
				resp = conn.getresponse()
				if not 200 <= resp.status <= 599:
					raise http.client.BadStatusLine(str(resp.status))
				data = resp.read(limit + 1)
				if len(data) > limit:
					raise http.client.HTTPException("upstream reply too large")
				if (
					resp.length
				):  # read(amt) does not raise when the upstream closes before its declared length
					raise http.client.IncompleteRead(data, resp.length)
				return resp.status, data, resp.getheader("Content-Type") or "application/json"
			finally:
				conn.close()

		def _health_status(self):
			"""One short, bounded upstream probe shared by every health request in HEALTH_CACHE_S."""
			with config.health_lock:
				cached = config.health
				if cached is not None and time.monotonic() - cached[0] < HEALTH_CACHE_S:
					return cached[1]
				try:
					status, _, _ = self._forward(
						"GET", "/health/ready", None, {}, timeout=HEALTH_TIMEOUT_S, limit=4096
					)
				except (OSError, http.client.HTTPException):
					status = 502
				config.health = (time.monotonic(), status)
				return status

		def _health(self):
			status = self._health_status()
			body = {"status": "ok" if status == 200 else "unavailable"}
			self._reply(status, json.dumps(body).encode(), close=status != 200)
			log("GET", None, "health", status, 0)

		def _prepare(self, bank):
			"""(route, target, body, headers, redactions) to forward, or (status, message, route) to refuse."""
			try:
				raw, pairs = parse_target(self.path)
			except BadTarget:
				return None, (400, "bad request target", "-")
			if tuple(raw[:3]) != BANK_PREFIX or len(raw) < 4:
				return None, (404, "not found", "-")
			try:
				bank_seg = _segment(raw[3], allow_escapes=False)
				matched = match_route(self.command, raw[4:])
			except BadTarget:
				return None, (400, "bad request target", "-")
			if bank_seg != bank or matched is None:
				return None, (404, "not found", "-")
			route, decoded, names = matched
			if pairs:
				if self.command != "GET":
					return None, (400, "query strings are only accepted on GET", route)
				if any(k not in names or len(v) > MAX_QUERY_VALUE for k, v in pairs):
					return None, (400, "query parameter not accepted", route)

			body, err = self._read_body()
			if err:
				return None, (err, "bad request body", route)
			redactions = 0
			headers = {"Authorization": f"Bearer {config.upstream_key}", "Accept": "application/json"}
			if route == "bank" and not body:
				return None, (400, "bank update needs a JSON body", route)
			if body:
				ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
				if self.command not in WRITE_METHODS or ctype != "application/json":
					return None, (415, "only JSON write bodies are accepted", route)
				try:
					payload = json.loads(body)
				except RecursionError:
					return None, (400, "JSON nested too deeply", route)
				except (ValueError, UnicodeDecodeError):
					return None, (400, "invalid JSON", route)
				if route == "bank" and (
					not isinstance(payload, dict) or not set(payload) <= BANK_MISSION_KEYS
				):
					return None, (400, "only reflect_mission and retain_mission may be set", route)
				try:
					payload, counts = redact_json(payload, config.secrets)
					body = json.dumps(payload, ensure_ascii=True).encode()
				except TextTooLarge:
					return None, (413, "text field too large", route)
				except RejectBody:
					return None, (400, "request body rejected", route)
				except RecursionError:
					return None, (400, "JSON nested too deeply", route)
				redactions = sum(counts.values())
				headers["Content-Type"] = "application/json"

			parts = [*BANK_PREFIX, bank, *decoded]
			target = "/" + "/".join(quote(p, safe=":@") for p in parts)
			if pairs:
				target += "?" + urlencode(pairs)
			return (route, target, body, headers, redactions), None

		def _handle(self):
			if self.path == "/health/ready" and self.command == "GET":
				# Same framing rules as every other request, checked before anything is answered: a body (or a
				# transfer coding) on a health check is refused and the connection closed, never left unread
				# for the next request on this connection to be parsed from.
				# From the headers alone: not a byte of a body is read (or buffered) before anything is answered.
				length, refused = self._framing()
				if refused or length:
					return self._error(refused or 400, "a health check carries no body", route="health")
				return self._health()
			bank = config.bank_for(self.headers.get("Authorization"))
			if bank is None:
				return self._error(401, "unauthorized")
			try:
				ready, refused = self._prepare(bank)
			except Exception as e:
				print(f"hindsight-proxy: request failed before forwarding: {type(e).__name__}", flush=True)
				return self._error(500, "internal error", bank)
			if refused:
				status, message, route = refused
				return self._error(status, message, bank, route)
			route, target, body, headers, redactions = ready
			try:
				status, data, ctype = self._forward(self.command, target, body, headers)
			except (OSError, http.client.HTTPException):
				return self._error(502, "upstream unavailable", bank, route)
			self._reply(status, data, ctype)
			log(self.command, bank, route, status, redactions)

		do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _handle

	return Handler


class _Server(ThreadingHTTPServer):
	daemon_threads = True
	# The kernel queue for connections not yet accepted: the default (5) resets a burst of clients before the
	# connection ceiling below can answer them with a clean 503.
	request_queue_size = MAX_CONNECTIONS

	def __init__(self, *args, **kwargs):
		self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
		super().__init__(*args, **kwargs)

	def process_request(self, request, client_address):
		# A thread per connection is only safe with a ceiling: unauthenticated clients can open connections too.
		if not self._slots.acquire(blocking=False):
			try:
				request.sendall(
					b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
				)
			except OSError:
				pass
			self.shutdown_request(request)
			return
		super().process_request(request, client_address)

	def process_request_thread(self, request, client_address):
		try:
			super().process_request_thread(request, client_address)
		finally:
			self._slots.release()


class _Server6(_Server):
	address_family = socket.AF_INET6


def serve(config, host=None):
	host = host or config.host
	check_listen_host(host, True, "listen host")
	server_class = _Server6 if ":" in host else _Server
	return server_class((host, config.port), make_handler(config))


def run(config, remote_listen=False):
	"""Serve until interrupted. Refuses a non-loopback listen address unless the operator allowed it."""
	check_listen_host(config.host, remote_listen, "listen host")
	server = serve(config)
	print(
		f"omp-hindsight-guard proxy on {config.host}:{server.server_address[1]}, "
		f"banks: {', '.join(sorted(config.bank_keys))}",
		flush=True,
	)
	try:
		server.serve_forever()
	except KeyboardInterrupt:
		pass
	finally:
		server.server_close()
	return 0
