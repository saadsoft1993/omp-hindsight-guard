"""Builders shared by the tests: a banks.json with key files, and a real proxy in front of a fake Hindsight."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from omp_hindsight_guard import proxy
from omp_hindsight_guard.config import Config, load_config, load_keys


def make_setup(config_dir: Path, banks: dict[str, list[str]], **proxy_extra) -> Config:
	"""Write banks.json and one distinct key file per bank (and the upstream) under config_dir; load it."""
	keys = config_dir / "keys"
	keys.mkdir(parents=True, exist_ok=True)
	keys.chmod(0o700)
	names = ["upstream", *banks]
	for i, name in enumerate(names):
		path = keys / f"{name}.key"
		path.write_text(f"{name}-{i:02d}-" + "k" * 40 + "\n")
		path.chmod(0o600)
	data = {
		"version": 1,
		"proxy": {"upstream_key_file": "keys/upstream.key", **proxy_extra},
		"banks": {name: {"key_file": f"keys/{name}.key", "roots": roots} for name, roots in banks.items()},
	}
	path = config_dir / "banks.json"
	path.write_text(json.dumps(data))
	path.chmod(0o600)
	return load_config(path)


class Upstream(BaseHTTPRequestHandler):
	"""A stand-in for Hindsight: answers 200 to everything and records what reached it."""

	protocol_version = "HTTP/1.1"
	seen: list = []  # noqa: RUF012
	missing: set = set()  # noqa: RUF012  banks Hindsight has not created yet: their listing answers 404

	def log_message(self, *args):
		pass

	def _handle(self):
		length = int(self.headers.get("Content-Length") or 0)
		body = self.rfile.read(length) if length else b""
		type(self).seen.append((self.command, self.path, self.headers.get("Authorization"), body))
		unborn = any(f"/banks/{bank}/" in self.path for bank in type(self).missing)
		data = json.dumps({"detail": "bank not found"} if unborn else {"ok": True}).encode()
		self.send_response(404 if unborn else 200)
		self.send_header("Content-Type", "application/json")
		self.send_header("Content-Length", str(len(data)))
		self.end_headers()
		self.wfile.write(data)

	do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _handle


def start(server):
	server.daemon_threads = True
	threading.Thread(target=server.serve_forever, daemon=True).start()
	return server


class Stack:
	"""A fake upstream and the real proxy configured from `config`, both on random loopback ports."""

	def __init__(self, config: Config, only_banks: tuple[str, ...] | None = None):
		Upstream.seen = []
		Upstream.missing = set()
		self.upstream = start(ThreadingHTTPServer(("127.0.0.1", 0), Upstream))
		keys = load_keys(config, only_banks)
		self.proxy_config = proxy.Config(
			f"http://127.0.0.1:{self.upstream.server_address[1]}", keys.upstream, keys.banks, 0
		)
		self.server = start(proxy.serve(self.proxy_config))
		self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
		self.upstream_url = f"http://127.0.0.1:{self.upstream.server_address[1]}"

	def close(self):
		self.server.shutdown()
		self.server.server_close()
		self.upstream.shutdown()
		self.upstream.server_close()
