# ruff: noqa: F811
"""Second verification pass (N1-N9): destination history across retries, header-only health rejection, document ids
and sizes on read-back, partly malformed routing tables, resolved Unicode roots, ancestors, failed-export pruning and
the first-export clock. Each failed before its fix."""

import socket
import time

import pytest

from omp_hindsight_guard import config as cfg
from omp_hindsight_guard import doctor
from omp_hindsight_guard import importer as im
from omp_hindsight_guard.redact import RejectBody, redact_json
from tests.helpers import make_setup
from tests.test_importer import FakeOpener, document_reply, row
from tests.test_proxy_hardening import BASE, KEY, FakeHindsight, raw, stack  # noqa: F401

OVERLAYS = {"alpha": ("https://memory.example:8898", "tok")}


# --- N1 ---------------------------------------------------------------------------------------------------------------


def two_rows_one_document():
	a = row("a-1", "working_memory", "1", "alpha", "project:a", "same text")
	b = row("a-2", "working_memory", "2", "alpha", "project:a", "same text")
	return a, b


def test_n1_a_subset_retry_after_a_failure_does_not_forget_the_other_source_row():
	s1, s2 = two_rows_one_document()
	ledger = im.Ledger()
	docs = im.dedupe([s1, s2])
	im.apply_ledger(docs, ledger)
	assert len(docs) == 1 and len(docs[0].members) == 2
	im.reserve(ledger, docs)
	doc_id = im.doc_id_of(docs[0])
	ledger.failed[doc_id] = ledger.pending.pop(doc_id)  # its operation failed
	retry = im.dedupe([s1])  # S2 is temporarily excluded
	im.apply_ledger(retry, ledger)
	im.reserve(ledger, retry)
	assert set(ledger.pending[doc_id]["sources"]) == {s1.source_key, s2.source_key}
	im.record(ledger, retry)
	assert ledger.sources[s2.source_key] == "alpha"  # confirmed for S1 only, but S2's destination survives
	moved = row("a-2", "working_memory", "2", "beta", "project:a", "same text")
	assert [why for _, _, why in im.apply_ledger(im.dedupe([moved]), ledger)] == ["source"]


def test_n1_a_second_failure_keeps_the_wider_history_too():
	s1, s2 = two_rows_one_document()
	ledger = im.Ledger()
	docs = im.dedupe([s1, s2])
	im.apply_ledger(docs, ledger)
	im.reserve(ledger, docs)
	doc_id = im.doc_id_of(docs[0])
	ledger.failed[doc_id] = ledger.pending.pop(doc_id)
	retry = im.dedupe([s1])
	im.apply_ledger(retry, ledger)
	im.reserve(ledger, retry)
	im.attach_operations(ledger, retry, ["550e8400-e29b-41d4-a716-446655440001"])
	import io

	im.reconcile(ledger, OVERLAYS, FakeOpener(op_status="failed"), io.StringIO())
	assert set(ledger.failed[doc_id]["sources"]) == {s1.source_key, s2.source_key}


# --- N2 ---------------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
	"headers", [b"Content-Length: 33554432", b"Transfer-Encoding: chunked", b"Content-Length: 1"]
)
def test_n2_a_health_request_with_a_body_is_refused_from_the_headers_alone(stack, headers):
	"""The declared body is never awaited: the answer comes while the client withholds every byte of it."""
	with socket.create_connection(("127.0.0.1", stack), timeout=3) as s:
		s.sendall(b"GET /health/ready HTTP/1.1\r\nHost: x\r\n" + headers + b"\r\n\r\n")  # and no body at all
		start = time.monotonic()
		data = s.recv(4096)
	assert data.startswith(b"HTTP/1.1 4") or data.startswith(b"HTTP/1.1 501")
	assert time.monotonic() - start < 2


def test_n2_a_routed_request_is_authenticated_before_its_body_is_read(stack):
	head = f"POST {BASE}/memories/recall HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer wrong\r\nContent-Length: 1000000\r\n\r\n".encode()
	with socket.create_connection(("127.0.0.1", stack), timeout=3) as s:
		s.sendall(head)  # no body
		assert s.recv(4096).startswith(b"HTTP/1.1 401")


# --- N5 ---------------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("bad", ["has space", "a/b", "tab\tid", "caf\u00e9"])
def test_n5_a_document_id_the_importer_could_not_read_back_is_refused_when_written(bad):
	with pytest.raises(RejectBody, match="invalid document id"):
		redact_json({"items": [{"content": "x", "document_id": bad}]})
	assert (
		redact_json({"items": [{"content": "x", "document_id": "mnemopi:alpha:work-1:w:a2@x.y_z"}]})[1]
		is not None
	)


def test_n5_generated_ids_use_only_characters_the_proxy_reads_back(stack):
	hostile = row("my label/x", "working_memory", "id with space/and slash", "alpha", "project:a", "text")
	doc_id = im.default_document_id(hostile)
	assert doc_id and all(c.isalnum() or c in ":_.-@" for c in doc_id)
	# and through the real proxy, not a fake opener: the request reaches the upstream with the id intact
	im.document_state("alpha", doc_id, "x", {"alpha": (f"http://127.0.0.1:{stack}", KEY)}, im.build_opener())
	assert FakeHindsight.seen[-1][1].endswith(f"/documents/{doc_id}")


# --- N6 ---------------------------------------------------------------------------------------------------------------


def test_n6_a_large_document_is_read_in_full_and_confirmed_by_its_hash():
	text = "x" * (3 << 20)  # 3 MiB of stored text: more than the 1 MiB an operation reply is limited to
	sha = im.content_hash(text)
	doc = "mnemopi:alpha:work:w:1"
	opener = FakeOpener(documents={doc: document_reply(doc, text=text, content_hash=sha)})
	assert im.document_state("alpha", doc, sha, OVERLAYS, opener) == "present"


def test_n6_a_reply_beyond_the_limit_is_reported_as_too_large_not_parsed_truncated(monkeypatch):
	monkeypatch.setattr(im, "MAX_DOCUMENT_RESPONSE", 2000)
	doc = "mnemopi:alpha:work:w:1"
	opener = FakeOpener(documents={doc: document_reply(doc, text="y" * 5000, content_hash="h")})
	assert im.document_state("alpha", doc, "h", OVERLAYS, opener) == "too-large"


# --- N4 ---------------------------------------------------------------------------------------------------------------


def parse_roots(tmp_path, roots):
	return cfg.parse_config(
		{
			"version": 1,
			"proxy": {"upstream_key_file": "u.key"},
			"banks": {"a": {"key_file": "k", "roots": roots}},
		},
		tmp_path / "banks.json",
	)


def test_n4_a_cased_non_ascii_target_is_fine_now_that_every_consumer_folds_only_ascii(tmp_path):
	"""The rule changed (third pass, M1): nothing but A-Z is folded anywhere, so no resolved path can disagree."""
	for name in ("stra\u00dfe", "\u00c9cole", "\u65e5\u672c\u8a9e"):
		target = tmp_path / name
		target.mkdir(exist_ok=True)
		alias = tmp_path / f"alias-{len(name)}"
		alias.symlink_to(target)
		parse_roots(tmp_path, [str(alias)])


# --- N8 ---------------------------------------------------------------------------------------------------------------


def test_n8_every_ancestor_is_checked_not_only_the_nearest(tmp_path):
	shared = tmp_path / "shared"
	shared.mkdir()
	shared.chmod(0o770)  # a group that is not known to be private, two levels above the private directory
	mid = shared / "mid"
	mid.mkdir(mode=0o700)
	with pytest.raises(cfg.ConfigError, match="writable by group or other"):
		cfg.makedirs_private(mid / "state")
	with pytest.raises(cfg.ConfigError, match="writable by group or other"):
		cfg.makedirs_private(mid)  # an existing leaf below the unsafe ancestor is no better
	shared.chmod(0o700)
	cfg.makedirs_private(mid / "state")


# --- N7 and N9 --------------------------------------------------------------------------------------------------------


def test_n9_the_first_export_clock_does_not_move_with_dump_retention(tmp_path):
	config = make_setup(tmp_path / "cfg", {"alpha": ["~/a"]})
	directory = tmp_path / "backups"
	directory.mkdir()
	(directory / "hindsight-2026-11-09-000000.dump").write_text(
		"x"
	)  # one fresh dump: retention keeps pruning
	(directory / ".first-run").write_text(f"{int(time.time()) - 20 * 86400}\n")
	checked = doctor.check_backup(directory, 26, config)
	assert [r.level for r in checked if r.name == "export alpha"] == ["fail"]
	(directory / ".first-run").write_text(f"{int(time.time()) - 2 * 86400}\n")
	assert [r.level for r in doctor.check_backup(directory, 26, config) if r.name == "export alpha"] == [
		"warn"
	]
