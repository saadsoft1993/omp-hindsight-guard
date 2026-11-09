# ruff: noqa: F811
"""The importer against Hindsight's real operation and document contract (hindsight-api 1.2.0).

Operation status (GET /v1/default/banks/{bank}/operations/{id}): `status` is one of pending, processing, completed,
failed, cancelled, not_found; a non-UUID id answers 400. A completed operation is pruned after
HINDSIGHT_API_OPERATION_RETENTION_DAYS (when above 0) and then reads not_found. A retain reply carries
`operation_id` (the first) and `operation_ids`. A document read (GET .../documents/{id}) answers 404 when absent
and carries `content_hash` (sha256 of the stored text) and `original_text` (null when text storage is off).
"""

import json

import pytest

from omp_hindsight_guard import importer as im
from tests.test_importer import (  # noqa: F401
	OP_ID,
	FakeOpener,
	document_reply,
	dry_digest,
	retain_reply,
	run_main,
	world,
	write_overlays,
)

OP_ID_2 = "550e8400-e29b-41d4-a716-446655440002"


def ledger_of(world):
	return json.loads((world["state"] / im.LEDGER_NAME).read_text())


def send_pending(world, **opener_args):
	write_overlays(world["overlays"])
	code, _ = run_main(
		world, "--send", "--confirm", dry_digest(world), opener=FakeOpener(op_status="pending", **opener_args)
	)
	assert code == 0 and ledger_of(world)["pending"]


def stored_documents(world, **extra):
	"""document id -> the server's reply for it, hashing what the ledger says was sent."""
	return {
		doc_id: document_reply(doc_id, content_hash=entry["sha"], **extra)
		for doc_id, entry in ledger_of(world)["pending"].items()
	}


# --- the retain reply -------------------------------------------------------------------------------------------


def test_the_retain_reply_fields_are_read_as_the_server_names_them():
	body = json.dumps(retain_reply(OP_ID)).encode()
	assert im.operation_ids(body) == [OP_ID]  # operation_id repeats operation_ids[0]: one entry, not two
	mixed = retain_reply(OP_ID) | {"operation_ids": [OP_ID, OP_ID_2]}
	assert im.operation_ids(json.dumps(mixed).encode()) == [OP_ID, OP_ID_2]  # mixed per-item strategies
	assert im.operation_ids(json.dumps({"success": True, "async": False}).encode()) == []


# --- every status the server can answer -------------------------------------------------------------------------


@pytest.mark.parametrize("status", ["pending", "processing"])
def test_open_operations_stay_pending(world, status):
	send_pending(world)
	code, text = run_main(world, "--reconcile", opener=FakeOpener(op_status=status))
	assert code == 0 and f"-> {status}" in text and "confirmed=0 failed=0 unconfirmed=0" in text
	assert run_main(world, "--count-unsynced")[1] == "unsynced=4\n"
	assert ledger_of(world)["pending"]


def test_a_completed_operation_confirms(world):
	send_pending(world)
	code, text = run_main(world, "--reconcile", opener=FakeOpener(op_status="completed"))
	assert code == 0 and "-> completed" in text
	assert run_main(world, "--count-unsynced")[1] == "unsynced=0\n"
	assert ledger_of(world)["pending"] == {}


@pytest.mark.parametrize("status", ["failed", "cancelled"])
def test_a_failed_or_cancelled_operation_releases_the_rows(world, status):
	send_pending(world)
	code, text = run_main(world, "--reconcile", opener=FakeOpener(op_status=status))
	assert code == 1 and f"-> {status}" in text and "failed=4" in text
	assert ledger_of(world)["pending"] == {}
	assert run_main(world, "--count-unsynced")[1] == "unsynced=4\n"  # offered again


def test_a_status_this_version_does_not_know_stays_pending(world):
	send_pending(world)
	code, text = run_main(world, "--reconcile", opener=FakeOpener(op_status="retrying"))
	assert code == 1 and "-> unknown" in text and "unconfirmed=4" in text and ledger_of(world)["pending"]


def test_a_non_uuid_operation_id_is_reported_as_invalid_and_stays_pending(world):
	write_overlays(world["overlays"])
	reply = retain_reply("not-a-uuid")
	run_main(world, "--send", "--confirm", dry_digest(world), opener=FakeOpener(reply=reply))
	assert all(e["operations"] == ["not-a-uuid"] for e in ledger_of(world)["pending"].values())
	opener = FakeOpener(op_status="completed")
	code, text = run_main(world, "--reconcile", opener=opener)
	assert code == 1 and "id=not-a-uuid -> invalid" in text  # the server answered 400; reported, not silent
	assert ledger_of(world)["pending"] and run_main(world, "--count-unsynced")[1] == "unsynced=4\n"


def test_an_answer_for_another_operation_is_not_trusted(world):
	class Wrong(FakeOpener):
		def open(self, req, timeout=None):
			if req.get_method() == "GET":
				self.gets.append(req)
				from tests.test_importer import FakeResponse, operation_reply

				return FakeResponse(200, operation_reply(OP_ID_2, "completed"))
			return super().open(req, timeout)

	send_pending(world)
	code, text = run_main(world, "--reconcile", opener=Wrong())
	assert code == 1 and "-> unknown" in text and ledger_of(world)["pending"]


# --- not_found: the operation was pruned --------------------------------------------------------------------------


def test_a_pruned_operation_is_confirmed_by_the_stored_document(world):
	send_pending(world)
	opener = FakeOpener(op_status="not_found", documents=stored_documents(world))
	code, text = run_main(world, "--reconcile", opener=opener)
	assert code == 0 and "-> not_found" in text and "-> present (not_found)" in text
	assert "confirmed=4 failed=0 unconfirmed=0 dropped=0 pending=0" in text
	assert run_main(world, "--count-unsynced")[1] == "unsynced=0\n"
	assert ledger_of(world)["pending"] == {}
	assert any("/documents/" in g.full_url for g in opener.gets)


def test_a_pruned_operation_with_no_document_is_reported_not_left_silent(world):
	send_pending(world)
	code, text = run_main(world, "--reconcile", opener=FakeOpener(op_status="not_found"))
	assert code == 1  # needs a decision
	assert text.count("unconfirmed bank=") == 4 and "operations: not_found; document absent" in text
	assert "confirmed=0 failed=0 unconfirmed=4 dropped=0 pending=0" in text
	assert ledger_of(world)["pending"] and run_main(world, "--count-unsynced")[1] == "unsynced=4\n"


def test_a_pruned_operation_with_other_content_is_not_confirmed(world):
	send_pending(world)
	other = {
		d: document_reply(d, content_hash="0" * 64, text="something else")
		for d in ledger_of(world)["pending"]
	}
	code, text = run_main(world, "--reconcile", opener=FakeOpener(op_status="not_found", documents=other))
	assert code == 1 and "operations: not_found; document different" in text
	assert run_main(world, "--count-unsynced")[1] == "unsynced=4\n"


def test_a_pruned_operation_with_an_unreadable_document_is_not_confirmed(world):
	send_pending(world)
	broken = dict.fromkeys(ledger_of(world)["pending"], 500)
	code, text = run_main(world, "--reconcile", opener=FakeOpener(op_status="not_found", documents=broken))
	assert code == 1 and "operations: not_found; document unreadable" in text


def test_pruned_and_completed_operations_of_one_document_need_the_document(world):
	write_overlays(world["overlays"])
	reply = retain_reply(OP_ID) | {"operation_ids": [OP_ID, OP_ID_2]}
	run_main(
		world, "--send", "--confirm", dry_digest(world), opener=FakeOpener(op_status="pending", reply=reply)
	)
	mixed = {OP_ID: "completed", OP_ID_2: "not_found"}
	code, text = run_main(world, "--reconcile", opener=FakeOpener(op_status=mixed))
	assert code == 1 and "unconfirmed=4" in text  # no document to vouch for the pruned half
	mixed_ok = FakeOpener(op_status=mixed, documents=stored_documents(world))
	code, text = run_main(world, "--reconcile", opener=mixed_ok)
	assert code == 0 and "confirmed=4" in text and ledger_of(world)["pending"] == {}


def test_an_open_operation_beside_a_pruned_one_keeps_the_document_pending(world):
	write_overlays(world["overlays"])
	reply = retain_reply(OP_ID) | {"operation_ids": [OP_ID, OP_ID_2]}
	run_main(
		world, "--send", "--confirm", dry_digest(world), opener=FakeOpener(op_status="pending", reply=reply)
	)
	opener = FakeOpener(
		op_status={OP_ID: "processing", OP_ID_2: "not_found"}, documents=stored_documents(world)
	)
	code, text = run_main(world, "--reconcile", opener=opener)
	assert code == 0 and "confirmed=0" in text and "unconfirmed=0" in text and ledger_of(world)["pending"]
	assert not any("/documents/" in g.full_url for g in opener.gets)  # nothing to vouch for yet


def test_a_failed_operation_beside_a_pruned_one_leaves_a_failed_record_when_the_document_is_absent(world):
	write_overlays(world["overlays"])
	reply = retain_reply(OP_ID) | {"operation_ids": [OP_ID, OP_ID_2]}
	run_main(
		world, "--send", "--confirm", dry_digest(world), opener=FakeOpener(op_status="pending", reply=reply)
	)
	opener = FakeOpener(op_status={OP_ID: "failed", OP_ID_2: "not_found"})
	code, text = run_main(world, "--reconcile", opener=opener)
	assert code == 1 and "failed=4" in text
	ledger = ledger_of(world)
	assert ledger["pending"] == {} and len(ledger["failed"]) == 4


def test_a_document_that_is_stored_wins_over_a_mixed_operation_outcome(world):
	"""One operation failed, but the document itself is on the server: it must not be released for another bank."""
	write_overlays(world["overlays"])
	reply = retain_reply(OP_ID) | {"operation_ids": [OP_ID, OP_ID_2]}
	run_main(
		world, "--send", "--confirm", dry_digest(world), opener=FakeOpener(op_status="pending", reply=reply)
	)
	opener = FakeOpener(op_status={OP_ID: "failed", OP_ID_2: "completed"}, documents=stored_documents(world))
	code, text = run_main(world, "--reconcile", opener=opener)
	assert code == 0 and "confirmed=4" in text and ledger_of(world)["pending"] == {}


# --- the document check on its own ------------------------------------------------------------------------------


OVERLAYS = {"alpha": ("https://memory.example:8898", "tok")}


def test_document_state_trusts_the_hash_or_the_stored_text_and_nothing_else():
	sha = im.content_hash("a lesson")
	doc = "mnemopi:alpha:work:wm:1"

	def state(reply):
		return im.document_state("alpha", doc, sha, OVERLAYS, FakeOpener(documents={doc: reply}))

	assert state(document_reply(doc, content_hash=sha)) == "present"
	assert state(document_reply(doc, text="a lesson")) == "present"  # hash not returned, text is
	assert state(document_reply(doc, text="a lesson ", content_hash="x")) == "different"
	assert state(document_reply(doc)) == "different"  # neither hash nor text: cannot be vouched for
	assert state(document_reply("another-id", content_hash=sha)) == "unreadable"  # not the document asked for
	assert state(404) == "absent" and state(500) == "unreadable" and state(403) == "unreadable"
	assert im.document_state("alpha", doc, sha, OVERLAYS, FakeOpener()) == "absent"


def test_document_ids_are_sent_as_one_path_segment():
	opener = FakeOpener(documents={})
	doc = "mnemopi:alpha:work wm:wm:a@b"
	im.document_state("alpha", doc, "x", OVERLAYS, opener)
	assert opener.gets[0].full_url.endswith(
		"/v1/default/banks/alpha/documents/mnemopi:alpha:work%20wm:wm:a@b"
	)
	assert opener.gets[0].get_header("Authorization") == "Bearer tok"
