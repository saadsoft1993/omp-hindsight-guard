# ruff: noqa: F811
"""Third review (importer): reservation lifecycle, unresolved resends, replies without operation evidence, the
cross-bank policy and deleted working directories. Each failed before its fix (finding ids R1.. in the names)."""

import json

import pytest

from omp_hindsight_guard import importer as im
from tests.test_importer import (  # noqa: F401
	OP_ID,
	FakeOpener,
	FakeResponse,
	document_reply,
	dry_digest,
	retain_reply,
	row,
	run_main,
	world,
	write_overlays,
)

OP_ID_2 = "550e8400-e29b-41d4-a716-446655440002"


def ledger_of(world):
	return json.loads((world["state"] / im.LEDGER_NAME).read_text())


def isolation_banks(world):
	"""source row -> bank as every isolation check sees the ledger now."""
	return im.effective_ledger(im.load_ledger(world["state"] / im.LEDGER_NAME)).sources


# --- R1: only a refusal made before anything was stored releases a reservation ----------------------------------


@pytest.mark.parametrize(
	"status", [500, 501, 502, 503, 504, 408, 302]
)  # 501: the proxy forwards the server's own
def test_r1_an_ambiguous_http_status_keeps_the_destination_on_record(world, status):
	"""A 502 is what the proxy answers when Hindsight accepted a write and then dropped the connection."""
	write_overlays(world["overlays"])
	code, text = run_main(world, "--send", "--confirm", dry_digest(world), opener=FakeOpener([status]))
	assert code == 1 and "outcome unknown" in text
	pending = ledger_of(world)["pending"]
	assert pending, "the reservation was erased"
	sources = isolation_banks(world)
	for entry in pending.values():
		assert all(sources[s] == entry["bank"] for s in entry["sources"])


@pytest.mark.parametrize("status", [400, 401, 403, 404, 413, 415, 422])
def test_r1_a_refusal_before_anything_was_stored_releases_it(world, status):
	write_overlays(world["overlays"])
	code, text = run_main(world, "--send", "--confirm", dry_digest(world), opener=FakeOpener([status]))
	assert code == 1 and "refused before anything was stored" in text
	assert ledger_of(world)["pending"] == {}


def test_r1_a_failed_operation_keeps_the_destination_but_allows_a_retry_to_the_same_bank(world):
	write_overlays(world["overlays"])
	run_main(world, "--send", "--confirm", dry_digest(world), opener=FakeOpener(op_status="pending"))
	run_main(world, "--reconcile", opener=FakeOpener(op_status="failed"))
	ledger = ledger_of(world)
	assert ledger["pending"] == {} and ledger["failed"]
	sources = isolation_banks(world)
	assert all(s in sources for entry in ledger["failed"].values() for s in entry["sources"])
	# offered again, to the same banks
	_, text = run_main(world, "--only-new")
	assert "requests=2 items=4" in text and "ledger_conflicts=0" in text
	code, _ = run_main(world, "--send", "--confirm", dry_digest(world, "--only-new"), opener=FakeOpener())
	assert code == 0 and ledger_of(world)["failed"] == {}  # confirmed: the record is gone


def test_r1_a_failed_record_blocks_a_move_to_another_bank():
	ledger = im.Ledger(failed={"mnemopi:alpha:a:w:1": {"bank": "alpha", "sha": "x", "sources": ["a:w:1"]}})
	moved = row("a", "working_memory", "1", "beta", "project:b", "text")
	assert [why for _, _, why in im.apply_ledger(im.dedupe([moved]), ledger)] == ["source"]


def test_r1_completed_plus_failed_without_the_document_is_a_failed_record_not_a_release(world):
	write_overlays(world["overlays"])
	reply = retain_reply(OP_ID) | {"operation_ids": [OP_ID, OP_ID_2]}
	run_main(
		world, "--send", "--confirm", dry_digest(world), opener=FakeOpener(op_status="pending", reply=reply)
	)
	opener = FakeOpener(op_status={OP_ID: "completed", OP_ID_2: "failed"})
	code, _ = run_main(world, "--reconcile", opener=opener)
	ledger = ledger_of(world)
	assert code == 1 and ledger["pending"] == {} and len(ledger["failed"]) == 4
	assert all(s in isolation_banks(world) for e in ledger["failed"].values() for s in e["sources"])


def test_r1_drop_unknown_is_the_only_way_to_forget_a_destination(world):
	write_overlays(world["overlays"])
	run_main(world, "--send", "--confirm", dry_digest(world), opener=FakeOpener([502]))
	assert ledger_of(world)["pending"]
	code, text = run_main(world, "--reconcile", opener=FakeOpener())
	assert (
		code == 1 and "unconfirmed=" in text and ledger_of(world)["pending"]
	)  # absent on the server: still reported
	code, text = run_main(world, "--reconcile", "--drop-unknown", opener=FakeOpener())
	assert code == 0 and "dropped=" in text and ledger_of(world)["pending"] == {}


def test_r1_drop_unknown_never_drops_an_operation_that_is_still_open(world):
	write_overlays(world["overlays"])
	run_main(world, "--send", "--confirm", dry_digest(world), opener=FakeOpener(op_status="processing"))
	run_main(world, "--reconcile", "--drop-unknown", opener=FakeOpener(op_status="processing"))
	assert ledger_of(world)["pending"]


# --- R2: a second send must not overwrite the evidence of the first ---------------------------------------------


def test_r2_unresolved_documents_are_held_back_not_resent(world):
	write_overlays(world["overlays"])
	run_main(world, "--send", "--confirm", dry_digest(world), opener=FakeOpener(op_status="pending"))
	before = ledger_of(world)["pending"]
	assert before and all(e["operations"] == [OP_ID] for e in before.values())
	_, text = run_main(world)
	assert "held_unresolved=4" in text and "requests=0 items=0" in text
	opener = FakeOpener(
		[422], op_status="pending"
	)  # the "retry" that used to overwrite the reservation, then release it
	_, text = run_main(world, "--send", "--confirm", dry_digest(world), opener=opener)
	assert opener.requests == [] and ledger_of(world)["pending"] == before  # evidence intact
	run_main(world, "--only-new", "--send", "--confirm", dry_digest(world, "--only-new"), opener=opener)
	assert opener.requests == [] and ledger_of(world)["pending"] == before


def test_r2_reserve_refuses_to_overwrite_an_unresolved_entry():
	ledger = im.Ledger()
	docs = im.dedupe([row("a", "working_memory", "1", "alpha", "project:a", "text")])
	im.apply_ledger(docs, ledger)
	im.reserve(ledger, docs)
	with pytest.raises(ValueError, match="unresolved"):
		im.reserve(ledger, docs)


def test_r2_a_document_resolved_by_reconcile_can_be_sent_again(world):
	write_overlays(world["overlays"])
	run_main(world, "--send", "--confirm", dry_digest(world), opener=FakeOpener(op_status="pending"))
	run_main(world, "--reconcile", opener=FakeOpener(op_status="completed"))
	_, text = run_main(world)
	assert "held_unresolved" not in text and "already_synced=4" in text


# --- R3: a reply without usable operation evidence is never "synced" --------------------------------------------


@pytest.mark.parametrize(
	"body",
	[b"", b"not json", b"[]", b"{}", b'{"success": true}', b'{"operation_id": 7}', b'{"operation_id": ""}'],
)
def test_r3_a_reply_without_a_usable_operation_id_leaves_everything_unconfirmed(world, body):
	class Reply(FakeOpener):
		def open(self, req, timeout=None):
			if req.get_method() == "POST":
				self.requests.append(req)
				return FakeResponse(202, body)
			return super().open(req, timeout)

	write_overlays(world["overlays"])
	code, text = run_main(world, "--send", "--confirm", dry_digest(world), opener=Reply())
	assert code == 1 and "no usable operation id" in text
	assert run_main(world, "--count-unsynced")[1] == "unsynced=4\n"
	assert len(ledger_of(world)["pending"]) == 4 and ledger_of(world)["documents"] == {}


def test_r3_the_stored_document_confirms_what_the_reply_could_not(world):
	class NoIds(FakeOpener):
		def open(self, req, timeout=None):
			if req.get_method() == "POST":
				self.requests.append(req)
				return FakeResponse(202, b'{"success": true}')
			return super().open(req, timeout)

	write_overlays(world["overlays"])
	run_main(world, "--send", "--confirm", dry_digest(world), opener=NoIds())
	documents = {d: document_reply(d, content_hash=e["sha"]) for d, e in ledger_of(world)["pending"].items()}
	code, text = run_main(world, "--reconcile", opener=FakeOpener(documents=documents))
	assert code == 0 and "confirmed=4" in text and run_main(world, "--count-unsynced")[1] == "unsynced=0\n"


# --- R5: one consistent cross-bank content policy, reported across the ledger and the current run ---------------


def test_r5_identical_text_first_seen_in_two_banks_in_one_run_is_listed_for_both():
	a = row("a-1", "working_memory", "1", "alpha", "project:a", "same text")
	b = row("b-1", "working_memory", "2", "beta", "project:b", "same text")
	docs = im.dedupe([a, b])
	assert im.apply_ledger(docs, im.Ledger()) == []
	listed = sorted((r.key, banks) for r, banks in im.content_copies(docs, im.Ledger()))
	assert listed == sorted([(a.key, ["beta"]), (b.key, ["alpha"])])


def test_r5_the_policy_is_the_same_whether_or_not_the_other_copy_is_in_this_run():
	"""Before the fix a B-only batch conflicted with A's content, but A+B together did not."""
	a = row("a-1", "working_memory", "1", "alpha", "project:a", "same text")
	b = row("b-1", "working_memory", "2", "beta", "project:b", "same text")
	ledger = im.Ledger()
	im.record(ledger, im.dedupe([a]))
	alone = im.apply_ledger(im.dedupe([b]), ledger)
	together = im.apply_ledger(im.dedupe([a, b]), ledger)
	assert alone == together == []


# --- R13: a row whose folder is gone is reviewed, never placed by a path nobody can check ---------------------------


def line_for(text, row_id):
	return next(entry for entry in text.splitlines() if f"\t{row_id}\t" in entry)


def test_r13_a_deleted_working_directory_needs_review(world):
	from tests.test_importer import make_bank

	gone = world["home"] / "work" / "alpha-app" / "deleted-checkout"
	conn = make_bank(
		world["root"],
		"gonebank-bbb222",
		working=[
			{"id": "gone1", "content": "from a checkout that no longer exists", "meta": {"cwd": str(gone)}}
		],
	)
	_, text = run_main(world)
	line = line_for(text, "gone1")
	assert "-> alpha" in line and "\treview\t" in line and "missing-cwd" in line  # not sent by default
	_, with_review = run_main(world, "--include-review")
	assert "\tsend\t" in line_for(with_review, "gone1")  # a person said yes
	conn.close()


def test_r13_deleted_directories_are_not_routing_evidence_for_rows_without_a_cwd(world):
	"""An orphan row follows its mnemopi bank's folders; folders that no longer exist cannot vouch for it."""
	from tests.test_importer import make_bank

	gone = world["home"] / "work" / "alpha-app" / "gone"
	conn = make_bank(
		world["root"],
		"orphans-aaa111",
		working=[
			{"id": "w1", "content": "has a cwd that is gone", "meta": {"cwd": str(gone)}},
			{"id": "w2", "content": "has no cwd at all", "meta": {}},
		],
	)
	_, text = run_main(world)
	orphan = line_for(text, "w2")
	assert "\treview\t" in orphan and "\tsend\t" not in orphan
	conn.close()
