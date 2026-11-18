import collections
import datetime as dt
import http.server
import io
import itertools
import json
import os
import sqlite3
import stat
import subprocess
import sys
import threading
import urllib.error
import urllib.parse
import uuid
from pathlib import Path

import pytest

from omp_hindsight_guard import importer as im
from omp_hindsight_guard import overlays as overlays_mod

SENTINEL = "SENTINEL-CONTENT-7f3a"
SECRET = "sk-test-SECRETVALUE"
MARK = "RESIDUAL-MARK"
TOKEN = "tok-overlay-DO-NOT-PRINT"
BANKS = [("alpha", "~/work/alpha-app"), ("alpha", "~/work/tools"), ("beta", "~/work/beta-site")]


def write_banks_json(path, allow_link_prefixes=()):
	"""A banks.json for the BANKS table above; the key files it names are not read by the importer."""
	path.write_text(
		json.dumps(
			{
				"version": 1,
				"proxy": {"upstream_key_file": "keys/upstream.key"},
				"banks": {
					"alpha": {"key_file": "keys/alpha.key", "roots": ["~/work/alpha-app", "~/work/tools"]},
					"beta": {"key_file": "keys/beta.key", "roots": ["~/work/beta-site"]},
				},
				"import": {"allow_link_prefixes": list(allow_link_prefixes)},
			}
		)
	)


WORKING_DDL = """CREATE TABLE working_memory (
	id TEXT PRIMARY KEY, content TEXT NOT NULL, embed_text TEXT, source TEXT, timestamp TEXT,
	session_id TEXT, importance REAL, metadata_json TEXT, veracity TEXT, superseded_by TEXT,
	valid_until TIMESTAMP, scope TEXT, created_at TIMESTAMP)"""
EPISODIC_DDL = """CREATE TABLE episodic_memory (
	rowid INTEGER PRIMARY KEY, id TEXT, content TEXT, source TEXT, timestamp TEXT, session_id TEXT,
	importance REAL, metadata_json TEXT, summary_of TEXT, binary_vector BLOB, valid_until TIMESTAMP,
	superseded_by TEXT)"""


def fake_redact(text, extra_secrets=()):
	counts = collections.Counter()
	if SECRET in text:
		counts["api_key"] = text.count(SECRET)
		text = text.replace(SECRET, "[REDACTED:api_key]")
	return text, counts


def fake_scan(text):
	return [("high-entropy", text.index(MARK))] if MARK in text else []


def make_bank(root, label, working=(), episodic=()):
	"""Create <root>/<label>/mnemopi.db in WAL mode; returns an open connection so the -wal stays."""
	bank = root / label
	bank.mkdir(parents=True)
	conn = sqlite3.connect(bank / "mnemopi.db")
	conn.execute("PRAGMA journal_mode=WAL")
	conn.execute("PRAGMA wal_autocheckpoint=0")
	conn.execute(WORKING_DDL)
	conn.execute(EPISODIC_DDL)
	for row in working:
		conn.execute(
			"INSERT INTO working_memory (id, content, source, timestamp, session_id, importance,"
			" metadata_json, superseded_by, valid_until, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
			(
				row["id"],
				row["content"],
				row.get("source", "learn-hook"),
				row.get("timestamp"),
				row.get("session_id", "s1"),
				row.get("importance", 0.7),
				json.dumps(row["meta"]) if "meta" in row else None,
				row.get("superseded_by"),
				row.get("valid_until"),
				row.get("created_at"),
			),
		)
	for row in episodic:
		conn.execute(
			"INSERT INTO episodic_memory (id, content, source, timestamp, session_id, importance,"
			" metadata_json) VALUES (?,?,?,?,?,?,?)",
			(
				row["id"],
				row["content"],
				"sleep_consolidation",
				row.get("timestamp"),
				None,
				0.5,
				json.dumps({"source": "consolidation"}),
			),
		)
	conn.commit()
	return conn


@pytest.fixture
def world(tmp_path):
	home = tmp_path / "home"
	lg = home / "work" / "beta-site" / "web"
	en = home / "work" / "alpha-app" / "ui"
	other = home / "work" / "other"
	for d in (lg, en, other):
		d.mkdir(parents=True)
	# a5 was written in a differently-cased spelling of beta-site: it must exist on case-sensitive filesystems too,
	# or the row would count as "folder no longer exists" (which needs review)
	(home / "Work" / "Beta-Site" / "Web").mkdir(parents=True, exist_ok=True)
	root = tmp_path / "banks"
	conns = [
		make_bank(
			root,
			"webapp-3tntylzrz3coh",
			working=[
				{
					"id": "a2",
					"content": f"{SENTINEL} lesson one {SECRET}",
					"meta": {"cwd": str(en)},
					"created_at": "2026-11-05T10:00:00.000Z",
				},
				{
					"id": "a1",
					"content": "beta fact",
					"meta": {"cwd": str(lg)},
					"timestamp": "1762336800",
					"superseded_by": "x",
				},
				{
					"id": "a3",
					"content": "shared lesson",
					"meta": {"cwd": str(en)},
					"timestamp": "2026-11-05 10:00:00",
					"valid_until": "2000-01-01T00:00:00Z",
				},
				{"id": "a4", "content": "   ", "meta": {"cwd": str(en)}},
				{
					"id": "a5",
					"content": "case lesson",
					"meta": {"cwd": str(home / "Work" / "Beta-Site" / "Web")},
				},
			],
			episodic=[{"id": "e1", "content": f"{SENTINEL} summary", "timestamp": "2026-11-06T00:00:00Z"}],
		),
		make_bank(
			root,
			"beta-site-39wpoq09nbpm1",
			working=[{"id": "b1", "content": "no cwd row", "meta": {"session_id": "s"}}],
		),
		make_bank(
			root,
			"ui-hvuqghjc1rgw",
			working=[{"id": "c1", "content": "shared lesson", "meta": {"cwd": str(home / "gone" / "Old")}}],
		),
		make_bank(
			root,
			"pilot-k2j3",
			working=[{"id": "p1", "content": "pilot fact", "meta": {"cwd": str(en)}}],
			episodic=[{"id": "pe", "content": "pilot summary"}],
		),
		make_bank(
			root,
			"other-zzz",
			working=[{"id": "o1", "content": f"{SENTINEL} private", "meta": {"cwd": str(other)}}],
		),
	]
	config = tmp_path / "banks.json"
	write_banks_json(config)
	yield {
		"home": home,
		"root": root,
		"lg": lg,
		"en": en,
		"overlays": tmp_path / "overlays",
		"state": tmp_path / "state",
		"config": config,
	}
	for conn in conns:
		conn.close()


def fake_resolver(path):
	return path.parent if path.name == "ui" else None


def run_main(world, *extra, opener=None, scan=fake_scan):
	buf = io.StringIO()
	code = im.main(
		[
			"--config",
			str(world["config"]),
			"--root",
			str(world["root"]),
			"--overlay-dir",
			str(world["overlays"]),
			"--state-dir",
			str(world["state"]),
			*extra,
		],
		resolver=fake_resolver,
		redact=fake_redact,
		scan=scan,
		home=world["home"],
		opener=opener,
		out=buf,
	)
	return code, buf.getvalue()


def digest_of(text):
	return next(line for line in text.splitlines() if line.startswith("digest=")).split("=", 1)[1]


def git(*args, cwd):
	env = {
		**os.environ,
		"GIT_AUTHOR_NAME": "t",
		"GIT_AUTHOR_EMAIL": "t@t",
		"GIT_COMMITTER_NAME": "t",
		"GIT_COMMITTER_EMAIL": "t@t",
	}
	subprocess.run(
		["git", "-c", "commit.gpgsign=false", *args], cwd=cwd, env=env, check=True, capture_output=True
	)


def test_tag_derivation_with_real_git(tmp_path):
	main = tmp_path / "Repo-Main"
	(main / "sub").mkdir(parents=True)
	git("init", "-q", cwd=main)
	git("commit", "-q", "--allow-empty", "-m", "init", cwd=main)
	worktree = tmp_path / "wt-feature"
	git("worktree", "add", "-q", str(worktree), cwd=main)
	bare = tmp_path / "Bare.git"
	bare.mkdir()
	git("init", "-q", "--bare", cwd=bare)
	plain = tmp_path / "Plain-Dir"
	plain.mkdir()
	odd = tmp_path / "We!rd (copy)"
	odd.mkdir()

	assert im.git_primary_root(worktree).resolve() == main.resolve()
	assert im.project_tag(str(main / "sub"), "x-1", im.git_primary_root) == "project:repo-main"
	assert im.project_tag(str(worktree), "x-1", im.git_primary_root) == "project:repo-main"
	assert im.project_tag(str(bare), "x-1", im.git_primary_root) == "project:bare.git"
	assert im.project_tag(str(plain), "x-1", im.git_primary_root) == "project:plain-dir"
	assert im.project_tag(str(tmp_path / "Missing"), "x-1", im.git_primary_root) == "project:missing"
	assert im.project_tag(str(odd), "x-1", im.git_primary_root) == "project:we_rd _copy_"
	assert im.project_tag(None, "Webapp-3tntylzrz3coh", im.git_primary_root) == ("project:webapp")


def test_parse_time_variants():
	assert im.iso(im.parse_time(1762336800)) == "2025-11-05T10:00:00Z"
	assert im.iso(im.parse_time(1762336800.5)) == "2025-11-05T10:00:00.500000Z"
	assert im.iso(im.parse_time(1762336800000)) == "2025-11-05T10:00:00Z"
	assert im.iso(im.parse_time("1762336800")) == "2025-11-05T10:00:00Z"
	assert im.iso(im.parse_time("2026-11-05T10:00:00.000Z")) == "2026-11-05T10:00:00Z"
	assert im.iso(im.parse_time("2026-11-05 15:00:00+05:00")) == "2026-11-05T10:00:00Z"
	assert im.iso(im.parse_time("2026-11-05 10:00:00")) == "2026-11-05T10:00:00Z"
	assert im.parse_time("not a date") is None
	assert im.parse_time(None) is None


def test_collect_reads_wal_snapshot_routes_and_redacts(world):
	before = sorted(p.name for p in (world["root"] / "webapp-3tntylzrz3coh").iterdir())
	assert "mnemopi.db-wal" in before
	rows, empty = im.collect(world["root"], world["home"], BANKS, fake_resolver, fake_redact, fake_scan)
	assert empty == 1
	by = {(r.label.split("-")[0], r.id): r for r in rows}
	assert len(rows) == 10
	assert by[("webapp", "a1")].bank == "beta"
	assert by[("webapp", "a1")].tag == "project:web"
	assert by[("webapp", "a1")].superseded and by[("webapp", "a1")].timestamp == "2025-11-05T10:00:00Z"
	assert by[("webapp", "a2")].tag == "project:alpha-app"
	assert by[("webapp", "a2")].bank == "alpha"
	assert SECRET not in by[("webapp", "a2")].content
	assert by[("webapp", "a2")].redactions == {"api_key": 1}
	assert by[("webapp", "a2")].timestamp == "2026-11-05T10:00:00Z"
	assert by[("webapp", "a3")].expired
	assert by[("webapp", "a5")].bank == "beta"
	e1 = by[("webapp", "e1")]
	assert (e1.table, e1.tag, e1.bank, e1.review) == (
		"episodic_memory",
		"project:webapp",
		None,
		True,
	)
	b1 = by[("beta", "b1")]
	assert (b1.bank, b1.tag, b1.review) == ("beta", "project:beta-site", True)
	c1 = by[("ui", "c1")]
	assert (c1.bank, c1.tag, c1.missing_cwd) == (None, "project:old", True)
	assert by[("other", "o1")].bank is None and not by[("other", "o1")].missing_cwd
	pe = by[("pilot", "pe")]
	assert (pe.bank, pe.tag, pe.review) == ("alpha", "project:alpha-app", False)
	assert sorted(p.name for p in (world["root"] / "webapp-3tntylzrz3coh").iterdir()) == before


def test_residual_scan_covers_every_redacted_field(world):
	conn = make_bank(
		world["root"],
		"ui-res",
		working=[{"id": "r1", "content": f"ok {MARK}", "source": MARK, "meta": {"cwd": str(world["en"])}}],
	)
	conn.close()
	rows, _ = im.collect(world["root"], world["home"], BANKS, fake_resolver, fake_redact, fake_scan)
	r1 = next(r for r in rows if r.id == "r1")
	assert r1.residual == [("content", "high-entropy", 3), ("source", "high-entropy", 0)]


def test_final_inherited_tags_are_scanned_before_quarantine(world):
	marker = "residual-mark"
	unsafe_cwd = world["home"] / "work" / "alpha-app" / marker
	unsafe_cwd.mkdir()
	conn = make_bank(
		world["root"],
		"unsafe-inheritance",
		working=[{"id": "owner", "content": "unsafe owner", "meta": {"cwd": str(unsafe_cwd)}}],
		episodic=[{"id": "orphan", "content": "unsafe orphan"}],
	)
	conn.close()
	conn = make_bank(
		world["root"],
		"residual-mark-123",
		working=[{"id": "safe-owner", "content": "safe owner", "meta": {"cwd": str(world["en"])}}],
		episodic=[{"id": "safe-orphan", "content": "safe orphan"}],
	)
	conn.close()

	def scan(text):
		return [("high-entropy", text.index(marker))] if marker in text else []

	rows, _ = im.collect(world["root"], world["home"], BANKS, fake_resolver, fake_redact, scan)
	by_id = {r.id: r for r in rows}
	for ident in ("owner", "orphan"):
		assert by_id[ident].tag == f"project:{marker}"
		assert by_id[ident].residual == [("tag", "high-entropy", len("project:"))]
	assert by_id["safe-orphan"].tag == "project:alpha-app"
	assert by_id["safe-orphan"].residual == []
	im.scan_row(by_id["orphan"], scan)
	assert by_id["orphan"].residual == [("tag", "high-entropy", len("project:"))]

	write_overlays(world["overlays"])
	opener = FakeOpener()
	code, _ = run_main(world, "--unattended", opener=opener, scan=scan)
	assert code == im.EXIT_QUARANTINE
	assert opener.requests
	for request in opener.requests:
		for item in json.loads(request.data)["items"]:
			for value in (item["content"], item["context"], *item["tags"], *item["metadata"].values()):
				assert not scan(value)
	assert any("safe orphan" in request.data.decode() for request in opener.requests)
	(quarantine,) = (world["state"] / "quarantine").glob("*.json")
	entries = json.loads(quarantine.read_text())["rows"]
	assert {entry["table"] for entry in entries} == {"working_memory", "episodic_memory"}
	assert len(entries) == 2
	assert all(entry["findings"] == [{"kind": "high-entropy", "field": "tag", "offset": 8}] for entry in entries)


def row(label, table, id_, bank, tag, content):
	return im.Row(
		label, table, id_, bank, tag, content, "src", None, "0.5", None, False, False, collections.Counter()
	)


def orphan(label, id_, tag="project:label"):
	r = row(label, "episodic_memory", id_, None, tag, "summary")
	r.has_cwd = False
	return r


def test_no_cwd_rows_inherit_when_bank_rows_agree():
	rows = [
		row("cf-1", "working_memory", "1", "beta", "project:webapp", "a"),
		row("cf-1", "working_memory", "2", "beta", "project:webapp", "b"),
		row("cf-1", "working_memory", "3", "beta", "project:web", "c"),
		orphan("cf-1", "e1"),
	]
	im.inherit_routing(rows, BANKS)
	assert (rows[3].bank, rows[3].tag, rows[3].review) == ("beta", "project:webapp", False)
	tie = [
		row("x-1", "working_memory", "1", "alpha", "project:zeta", "a"),
		row("x-1", "working_memory", "2", "alpha", "project:alpha", "b"),
		orphan("x-1", "e1"),
	]
	im.inherit_routing(tie, BANKS)
	assert (tie[2].bank, tie[2].tag) == ("alpha", "project:alpha")


def test_no_cwd_rows_need_review_and_never_default_to_alpha():
	mixed = [
		row("cf-1", "working_memory", "1", "beta", "project:webapp", "a"),
		row("cf-1", "working_memory", "2", "alpha", "project:ui", "b"),
		orphan("cf-1", "e1", tag="project:cf"),
	]
	im.inherit_routing(mixed, BANKS)
	assert (mixed[2].bank, mixed[2].tag, mixed[2].review) == (None, "project:cf", True)
	assert not mixed[0].review and not mixed[1].review
	partly = [
		row("cf-1", "working_memory", "1", "beta", "project:webapp", "a"),
		row("cf-1", "working_memory", "2", None, "project:other", "b"),
		orphan("cf-1", "e1"),
	]
	im.inherit_routing(partly, BANKS)
	assert (partly[2].bank, partly[2].review) == ("beta", True)
	outside = [row("x-1", "working_memory", "1", None, "project:x", "a"), orphan("x-1", "e1")]
	im.inherit_routing(outside, BANKS)
	assert (outside[1].bank, outside[1].review) == (None, True)
	for label, bank in (
		("beta-site-39wpoq09nbpm1", "beta"),
		("tools-1", "alpha"),
		("webapp-3t", None),
	):
		alone = [orphan(label, "e1")]
		im.inherit_routing(alone, BANKS)
		assert (alone[0].bank, alone[0].review) == (bank, True)


def test_skip_reasons_and_flags():
	base = row("pilot-k2", "working_memory", "1", "alpha", "project:x", "a")
	none = row("x-1", "working_memory", "2", None, "project:x", "b")
	review = orphan("beta-site-1", "3")
	review.bank, review.review = "beta", True
	lost = orphan("cf-1", "4")
	lost.review = True
	old = row("x-1", "working_memory", "5", "alpha", "project:x", "c")
	old.superseded = True
	gone = row("x-1", "working_memory", "6", "alpha", "project:x", "d")
	gone.expired = True
	rows = [base, none, review, lost, old, gone]

	def reasons(*args):
		return [im.skip_reason(r, *args) for r in rows]

	assert reasons(False, False, []) == [None, "skip", "review", "review", "superseded", "expired"]
	assert reasons(True, True, []) == [None, "skip", None, "skip", None, None]
	assert reasons(False, False, ["PILOT", "beta-site-1"]) == [
		"excluded-label",
		"skip",
		"review",
		"review",
		"superseded",
		"expired",
	]
	assert reasons(True, False, ["beta"])[2] == "excluded-label"
	chosen, skipped = im.select(rows, False, False, [])
	assert chosen == [base] and [reason for _, reason in skipped] == reasons(False, False, [])[1:]


def test_dedupe_is_deterministic_and_bank_scoped():
	rows = [
		row("b-1", "working_memory", "9", "alpha", "project:b", "same"),
		row("a-1", "working_memory", "5", "alpha", "project:a", "same"),
		row("a-1", "episodic_memory", "1", "alpha", "project:c", "same"),
		row("c-1", "working_memory", "1", "beta", "project:l", "same"),
		row("a-1", "working_memory", "7", "alpha", "project:a", "other"),
	]
	expected = None
	for perm in itertools.permutations(rows):
		docs = [(d.row.key, d.row.bank, d.tags, d.merged, len(d.members)) for d in im.dedupe(perm)]
		expected = expected or docs
		assert docs == expected
	assert expected == [
		(("a-1", "episodic_memory", "1"), "alpha", ["project:a", "project:b", "project:c"], 3, 3),
		(("a-1", "working_memory", "7"), "alpha", ["project:a"], 1, 1),
		(("c-1", "working_memory", "1"), "beta", ["project:l"], 1, 1),
	]


def test_item_has_bank_in_document_id_and_string_metadata():
	r = im.Row(
		"cf-1",
		"episodic_memory",
		"e1",
		"alpha",
		"project:cf",
		"text",
		"sleep_consolidation",
		None,
		"0.7",
		"2026-11-05T10:00:00Z",
		True,
		False,
		collections.Counter(),
	)
	item = im.to_item(im.Doc(r, ["project:cf"], 1))
	assert item == {
		"content": "text",
		"context": "mnemopi import: sleep_consolidation",
		"document_id": "mnemopi:alpha:cf-1:e:e1",
		"tags": ["project:cf"],
		"metadata": {
			"source": "sleep_consolidation",
			"importance": "0.7",
			"mnemopi_table": "episodic_memory",
			"superseded": "true",
		},
		"timestamp": "2026-11-05T10:00:00Z",
	}
	assert all(isinstance(v, str) for v in item["metadata"].values())
	r.id = "id with #weird?chars"
	assert im.to_item(im.Doc(r, ["project:cf"], 1))["document_id"].startswith(
		"mnemopi:alpha:cf-1:e:id_with__weird_chars@h"
	)


def test_batches_group_by_bank_and_tag_set():
	docs = [
		im.Doc(row("a-1", "working_memory", f"{i:02d}", "alpha", "project:a", f"c{i}"), ["project:a"], 1)
		for i in range(20)
	]
	docs.append(
		im.Doc(row("a-1", "working_memory", "x", "alpha", "project:a", "x"), ["project:a", "project:b"], 2)
	)
	docs.append(im.Doc(row("l-1", "working_memory", "y", "beta", "project:a", "y"), ["project:a"], 1))
	out = im.batches(docs)
	assert [(b, t, len(d)) for b, t, d in out] == [
		("alpha", ("project:a",), 16),
		("alpha", ("project:a",), 4),
		("alpha", ("project:a", "project:b"), 1),
		("beta", ("project:a",), 1),
	]
	for entry, (_, tags, _) in zip(im.payload(out), out, strict=True):
		assert all(item["tags"] == list(tags) for item in entry["items"])
		assert all("async" not in item for item in entry["items"])


def test_dry_run_prints_no_content(world):
	code, text = run_main(world)
	assert code == 0
	assert SENTINEL not in text and SECRET not in text and "shared lesson" not in text
	assert str(world["home"]) not in text
	assert (
		"webapp-3tntylzrz3coh\tworking_memory\ta2\t-> alpha\tproject:alpha-app\t"
		"len=51\tredactions=api_key=1\tresidual=none\tsend"
	) in text
	assert "ui-hvuqghjc1rgw\tworking_memory\tc1\t-> -\tproject:old\tlen=13\tredactions=none\t" in text
	assert "\tskip\tflags=missing-cwd" in text
	assert "skip:\tother-zzz\tworking_memory\to1\tskip" in text
	assert "skip:\tui-hvuqghjc1rgw\tworking_memory\tc1\tskip" in text
	assert "skip:\twebapp-3tntylzrz3coh\tepisodic_memory\te1\treview" in text
	assert "skip:\tbeta-site-39wpoq09nbpm1\tworking_memory\tb1\treview" in text
	assert "skip:\twebapp-3tntylzrz3coh\tworking_memory\ta1\tsuperseded" in text
	assert "skip:\twebapp-3tntylzrz3coh\tworking_memory\ta3\texpired" in text
	assert "review:\twebapp-3tntylzrz3coh\tepisodic_memory\te1\t-> -" in text
	assert "review:\tbeta-site-39wpoq09nbpm1\tworking_memory\tb1\t-> beta" in text
	assert "rows=10 (working_memory=8, episodic_memory=2) to_send=4 after_dedupe=4" in text
	case_variant_missing = not (world["home"] / "Work" / "Beta-Site" / "Web").exists()
	assert f"superseded=1 expired=1 review=2 missing_cwd={1 + case_variant_missing}" in text
	assert "skipped: skip=2 review=2 excluded-label=0 superseded=1 expired=1 empty=1" in text
	assert "target\talpha\tproject:alpha-app\t3" in text
	assert "target\tbeta\tproject:web\t1" in text
	assert "residual: none" in text and "ledger_conflicts=0" in text
	assert "requests=2 items=4" in text
	assert "already_synced=0 unsynced=4" in text
	assert len(digest_of(text)) == 64
	assert not world["overlays"].exists()


def test_exclude_label_and_include_flags(world):
	_, text = run_main(world, "--exclude-label", "pilot", "--exclude-label", "nomatch")
	assert "skip:\tpilot-k2j3\tworking_memory\tp1\texcluded-label" in text
	assert "skipped: skip=2 review=2 excluded-label=2" in text
	_, text = run_main(world, "--include-review", "--include-superseded")
	assert "skip:\twebapp-3tntylzrz3coh\tepisodic_memory\te1\tskip" in text
	assert "target\tbeta\tproject:beta-site\t1" in text
	assert "skipped: skip=3 review=0 excluded-label=0 superseded=0 expired=0 empty=1" in text


def test_digest_is_stable_and_tracks_items(world):
	_, first = run_main(world)
	_, second = run_main(world)
	assert digest_of(first) == digest_of(second)
	_, wider = run_main(world, "--include-superseded")
	assert digest_of(wider) != digest_of(first)
	conn = sqlite3.connect(world["root"] / "pilot-k2j3" / "mnemopi.db")
	conn.execute("UPDATE working_memory SET content = 'pilot fact!' WHERE id = 'p1'")
	conn.commit()
	conn.close()
	_, changed = run_main(world)
	assert digest_of(changed) != digest_of(first)


def test_residual_lines_and_send_refusal(world):
	conn = make_bank(
		world["root"],
		"ui-res",
		working=[{"id": "r1", "content": f"left {MARK}", "meta": {"cwd": str(world["en"])}}],
	)
	conn.close()
	write_overlays(world["overlays"])
	code, text = run_main(world)
	assert "residual:\tui-res\tworking_memory\tr1\thigh-entropy\tcontent:5" in text
	assert "residual: high-entropy=1" in text and MARK not in text
	opener = FakeOpener()
	code, text = run_main(world, "--send", "--confirm", digest_of(text), opener=opener)
	assert code == im.EXIT_RESIDUAL and opener.requests == []
	assert "nothing sent" in text
	assert len(list((world["state"] / "exports").glob("hindsight-import-*.jsonl"))) == 1


def test_write_redacted_is_private_and_not_overwritten(world, tmp_path):
	target = tmp_path / "out" / "redacted.jsonl"
	code, _ = run_main(world, "--write-redacted", str(target))
	assert code == 0
	assert stat.S_IMODE(target.stat().st_mode) == 0o600
	lines = [json.loads(line) for line in target.read_text().splitlines()]
	assert [entry["bank"] for entry in lines] == ["alpha", "alpha", "alpha", "beta"]
	assert SECRET not in target.read_text() and "[REDACTED:api_key]" in target.read_text()
	assert {entry["item"]["document_id"] for entry in lines} >= {"mnemopi:alpha:pilot-k2j3:w:p1"}
	target.write_text("keep")
	code, _ = run_main(world, "--write-redacted", str(target))
	assert code == 2 and target.read_text() == "keep"
	code, _ = run_main(world, "--write-redacted", str(target), "--force")
	assert code == 0 and target.read_text() != "keep"


# Response shapes copied from hindsight-api 1.2.0 (RetainResponse, OperationStatusResponse, DocumentResponse).
OP_ID = "550e8400-e29b-41d4-a716-446655440001"


def retain_reply(operation_id=OP_ID):
	return {
		"success": True,
		"bank_id": "alpha",
		"items_count": 2,
		"async": True,
		"operation_id": operation_id,
		"operation_ids": [operation_id],
		"usage": None,
	}


def operation_reply(operation_id, status, error=None):
	done = status in ("completed", "failed", "cancelled")
	return {
		"operation_id": operation_id,
		"status": status,
		"operation_type": "retain",
		"id": operation_id,
		"task_type": "retain",
		"mental_model_id": None,
		"created_at": "2026-11-09T10:30:00Z",
		"updated_at": "2026-11-09T10:31:30Z",
		"completed_at": "2026-11-09T10:31:30Z" if done else None,
		"error_message": error,
	}


def document_reply(document_id, text=None, content_hash=None):
	return {
		"id": document_id,
		"bank_id": "alpha",
		"original_text": text,
		"content_hash": content_hash,
		"created_at": "2026-11-09T10:30:00Z",
		"updated_at": "2026-11-09T10:30:00Z",
		"memory_unit_count": 3,
		"nodes_by_fact_type": None,
		"tags": [],
		"document_metadata": None,
		"retain_params": None,
	}


class FakeResponse:
	def __init__(self, status, body=None):
		self.status = status
		body = retain_reply() if body is None else body
		self.body = body if isinstance(body, bytes) else json.dumps(body).encode()

	def read(self, n=-1):
		return self.body if n is None or n < 0 else self.body[:n]  # a bounded read really is bounded

	def close(self):
		pass


class FakeOpener:
	"""POSTs consume `statuses`. GETs are kept apart in `gets`: an operation poll answers `op_status` (one status
	for all, or a dict by operation id) in the server's response shape, and 400 for an id that is not a UUID, as the
	server does; a document read answers from `documents` (document id -> body) or 404."""

	def __init__(self, statuses=None, op_status="completed", documents=None, reply=None):
		self.statuses = list(statuses or [])
		self.requests = []
		self.gets = []
		self.op_status = op_status
		self.documents = documents or {}
		self.reply = reply

	def open(self, req, timeout=None):
		assert timeout == 60
		if req.get_method() == "GET":
			self.gets.append(req)
			_, _, tail = req.full_url.partition("/v1/default/banks/")
			_, kind, ident = tail.split("/", 2)
			ident = urllib.parse.unquote(ident)
			if kind == "operations":
				try:
					uuid.UUID(ident)
				except ValueError:
					raise urllib.error.HTTPError(req.full_url, 400, "bad id", {}, None) from None
				status = self.op_status[ident] if isinstance(self.op_status, dict) else self.op_status
				return FakeResponse(200, operation_reply(ident, status))
			if ident not in self.documents:
				raise urllib.error.HTTPError(req.full_url, 404, "Document not found", {}, None)
			doc = self.documents[ident]
			if isinstance(doc, int):
				raise urllib.error.HTTPError(req.full_url, doc, "err", {}, None)
			return FakeResponse(200, doc)
		self.requests.append(req)
		status = self.statuses.pop(0) if self.statuses else 202
		if isinstance(status, Exception):
			raise status
		if status >= 300:
			raise urllib.error.HTTPError(req.full_url, status, "err", {}, None)
		return FakeResponse(status, self.reply)


def write_overlays(d, url="https://memory.example:8898/", mode=0o600):
	d.mkdir(exist_ok=True)
	for bank in ("alpha", "beta"):
		path = d / f"{bank}.yml"
		path.write_text(
			f"memory:\n  backend: hindsight\nhindsight:\n  apiUrl: {url}\n"
			f"  apiToken: {TOKEN}-{bank}\n  bankId: {bank}\n"
		)
		path.chmod(mode)
	return d


def dry_digest(world, *extra):
	return digest_of(run_main(world, *extra)[1])


def test_send_needs_matching_confirm(world):
	write_overlays(world["overlays"])
	for extra in ([], ["--confirm", "0" * 64]):
		opener = FakeOpener()
		code, text = run_main(world, "--send", *extra, opener=opener)
		assert code == im.EXIT_CONFIRM and opener.requests == []
		assert "nothing sent" in text
	assert not (world["state"] / "exports").exists()
	assert not (world["state"] / im.LEDGER_NAME).exists()


def test_send_posts_async_batches_writes_backup_and_ledger(world):
	write_overlays(world["overlays"])
	opener = FakeOpener()
	code, text = run_main(world, "--send", "--confirm", dry_digest(world), opener=opener)
	assert code == 0
	assert TOKEN not in text and SENTINEL not in text
	assert "sent requests=2 items=4" in text
	assert f"-> 202 operations={OP_ID}" in text
	sent = []
	for req in opener.requests:
		body = json.loads(req.data)
		assert req.get_method() == "POST"
		assert body["async"] is True and set(body) == {"async", "items"}
		bank = req.full_url.rsplit("/", 2)[-2]
		assert req.full_url == f"https://memory.example:8898/v1/default/banks/{bank}/memories"
		assert req.get_header("Authorization") == f"Bearer {TOKEN}-{bank}"
		assert len({tuple(i["tags"]) for i in body["items"]}) == 1
		for item in body["items"]:
			assert all(isinstance(v, str) for v in item["metadata"].values())
			assert SECRET not in item["content"]
			sent.append((bank, item["document_id"]))
	assert sorted(sent) == [
		("alpha", "mnemopi:alpha:pilot-k2j3:e:pe"),
		("alpha", "mnemopi:alpha:pilot-k2j3:w:p1"),
		("alpha", "mnemopi:alpha:webapp-3tntylzrz3coh:w:a2"),
		("beta", "mnemopi:beta:webapp-3tntylzrz3coh:w:a5"),
	]
	(backup,) = (world["state"] / "exports").glob("hindsight-import-*.jsonl")
	assert stat.S_IMODE(backup.stat().st_mode) == 0o600
	assert len(backup.read_text().splitlines()) == 4
	ledger_path = world["state"] / im.LEDGER_NAME
	assert stat.S_IMODE(ledger_path.stat().st_mode) == 0o600
	ledger = json.loads(ledger_path.read_text())
	assert ledger["sources"]["webapp-3tntylzrz3coh:w:a5"] == "beta"
	assert {d for _, d in sent} == set(ledger["documents"])
	assert SENTINEL not in ledger_path.read_text()
	# A re-run is identical and sends the same document ids again.
	opener2 = FakeOpener()
	code, _ = run_main(world, "--send", "--confirm", dry_digest(world), opener=opener2)
	assert code == 0
	again = sorted(i["document_id"] for r in opener2.requests for i in json.loads(r.data)["items"])
	assert again == sorted(d for _, d in sent)


def test_ledger_written_after_each_successful_batch(world):
	write_overlays(world["overlays"])
	opener = FakeOpener([202, 500])
	code, text = run_main(world, "--send", "--confirm", dry_digest(world), opener=opener)
	assert code == 1 and len(opener.requests) == 2
	assert "-> 500" in text and TOKEN not in text
	ledger = json.loads((world["state"] / im.LEDGER_NAME).read_text())
	assert {v["bank"] for v in ledger["documents"].values()} == {"alpha"}
	assert len(ledger["documents"]) == 3


def seed_ledger(world, ledger):
	world["overlays"].mkdir(exist_ok=True)
	im.save_ledger(world["state"] / im.LEDGER_NAME, ledger)


def test_ledger_refuses_cross_bank_moves(world):
	write_overlays(world["overlays"])
	seed_ledger(world, im.Ledger(sources={"webapp-3tntylzrz3coh:w:a5": "alpha"}))
	_, text = run_main(world)
	assert "ledger-conflict:\twebapp-3tntylzrz3coh\tworking_memory\ta5\t-> beta\t" in text
	assert "earlier=alpha\tsource" in text and "ledger_conflicts=1" in text
	opener = FakeOpener()
	code, text = run_main(world, "--send", "--confirm", digest_of(text), opener=opener)
	assert code == im.EXIT_LEDGER and opener.requests == []

	sha = im.content_hash("case lesson")
	seed_ledger(world, im.Ledger(contents={sha: {"alpha": "mnemopi:alpha:x:w:9"}}))
	_, text = run_main(world)
	# Policy: a distinct source row may carry text another bank also holds. It is listed, never silently allowed.
	assert "ledger_conflicts=0" in text and "also-in=alpha" in text

	seed_ledger(world, im.Ledger(sources={"other-zzz:w:o1": "alpha"}))
	_, text = run_main(world)
	assert "ledger-conflict:\tother-zzz\tworking_memory\to1\t-> -\tearlier=alpha\tunrouted" in text


def test_ledger_reuses_document_id_for_same_content_and_bank(world):
	sha = im.content_hash("pilot fact")
	seed_ledger(
		world,
		im.Ledger(
			documents={"mnemopi:alpha:old:w:1": {"bank": "alpha", "sha": sha}},
			contents={sha: {"alpha": "mnemopi:alpha:old:w:1"}},
			sources={"old:w:1": "alpha"},
		),
	)
	target = world["overlays"].parent / "r.jsonl"
	code, text = run_main(world, "--write-redacted", str(target))
	assert code == 0 and "ledger_conflicts=0" in text
	ids = {json.loads(line)["item"]["document_id"] for line in target.read_text().splitlines()}
	assert "mnemopi:alpha:old:w:1" in ids and "mnemopi:alpha:pilot-k2j3:w:p1" not in ids


def sent_ids(opener):
	return sorted(i["document_id"] for r in opener.requests for i in json.loads(r.data)["items"])


def test_only_new_sends_rows_missing_from_the_ledger(world):
	write_overlays(world["overlays"])
	# The alpha batch succeeds, the beta one fails: the ledger has 3 of the 4 rows.
	code, _ = run_main(world, "--send", "--confirm", dry_digest(world), opener=FakeOpener([202, 422]))
	assert code == 1
	_, full = run_main(world)
	assert "already_synced=3 unsynced=1" in full and "requests=2 items=4" in full
	_, new = run_main(world, "--only-new")
	assert "already_synced=3 unsynced=1" in new and "requests=1 items=1" in new
	assert "target\tbeta\tproject:web\t1" in new and "target\talpha" not in new
	assert digest_of(new) != digest_of(full)
	assert run_main(world, "--count-unsynced")[1] == "unsynced=1\n"
	# Changed content is unsynced again, under the same document id.
	conn = sqlite3.connect(world["root"] / "pilot-k2j3" / "mnemopi.db")
	conn.execute("UPDATE working_memory SET content = 'pilot fact!' WHERE id = 'p1'")
	conn.commit()
	conn.close()
	_, new = run_main(world, "--only-new")
	assert "already_synced=2 unsynced=2" in new and "requests=2 items=2" in new
	opener = FakeOpener()
	code, _ = run_main(world, "--only-new", "--send", "--confirm", digest_of(new), opener=opener)
	assert code == 0
	assert sent_ids(opener) == [
		"mnemopi:alpha:pilot-k2j3:w:p1",
		"mnemopi:beta:webapp-3tntylzrz3coh:w:a5",
	]
	assert run_main(world, "--count-unsynced")[1] == "unsynced=0\n"
	_, new = run_main(world, "--only-new")
	assert "already_synced=4 unsynced=0" in new and "requests=0 items=0" in new
	# Without --only-new a re-run still sends everything (idempotent upserts).
	assert "requests=2 items=4" in run_main(world)[1]


def test_count_unsynced_prints_one_line_and_no_content(world, monkeypatch):
	conn = make_bank(
		world["root"],
		"ui-res",
		working=[{"id": "r1", "content": f"{SENTINEL} {MARK} {SECRET}", "meta": {"cwd": str(world["en"])}}],
	)
	conn.close()
	monkeypatch.setitem(sys.modules, "yaml", None)
	scanned = []
	code, text = run_main(world, "--count-unsynced", scan=lambda t: scanned.append(t) or fake_scan(t))
	assert code == 0 and text == "unsynced=5\n" and scanned == []
	code, text = run_main(world, "--count-unsynced", "--include-review")
	assert code == 0 and text == "unsynced=6\n"
	with pytest.raises(SystemExit):
		run_main(world, "--count-unsynced", "--send")


def test_send_needs_valid_private_overlay(world, tmp_path):
	opener = FakeOpener()
	code, _ = run_main(world, "--send", "--confirm", dry_digest(world), opener=opener)
	assert code == 2 and opener.requests == []
	for url, mode in (("https://memory.example/", 0o644), ("http://memory.example:8888", 0o600)):
		write_overlays(world["overlays"], url=url, mode=mode)
		for p in (world["state"] / "exports").glob("*"):
			p.unlink()
		code, _ = run_main(world, "--send", "--confirm", dry_digest(world), opener=opener)
		assert code == 2 and opener.requests == []
	write_overlays(world["overlays"], url="http://127.0.0.1:8888")
	assert overlays_mod.load_overlay(world["overlays"] / "alpha.yml") == (
		"http://127.0.0.1:8888",
		f"{TOKEN}-alpha",
	)
	write_overlays(world["overlays"], url="http://localhost:8888/")
	assert overlays_mod.load_overlay(world["overlays"] / "beta.yml")[0] == "http://localhost:8888"


def test_redirect_is_a_failure(world):
	write_overlays(world["overlays"])
	opener = FakeOpener([302])
	code, text = run_main(world, "--send", "--confirm", dry_digest(world), opener=opener)
	assert code == 1 and len(opener.requests) == 1 and "-> 302" in text and "outcome unknown" in text
	ledger = json.loads((world["state"] / im.LEDGER_NAME).read_text())
	# a redirect proves nothing about what the server stored: the destination stays on record
	assert ledger["pending"] and ledger["documents"] == {}


def test_real_opener_does_not_follow_redirects():
	hits = []

	class Handler(http.server.BaseHTTPRequestHandler):
		def do_POST(self):
			hits.append((self.path, self.headers.get("Authorization")))
			self.send_response(302)
			self.send_header("Location", "/elsewhere")
			self.send_header("Content-Length", "0")
			self.end_headers()

		do_GET = do_POST

		def log_message(self, *args):
			pass

	server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
	thread = threading.Thread(target=server.serve_forever, daemon=True)
	thread.start()
	try:
		url = f"http://127.0.0.1:{server.server_address[1]}"
		doc = im.Doc(row("a-1", "working_memory", "1", "alpha", "project:a", "x"), ["project:a"], 1)
		buf = io.StringIO()
		code = im.send([("alpha", ("project:a",), [doc])], {"alpha": (url, "k")}, im.build_opener(), buf)
	finally:
		server.shutdown()
		server.server_close()
	assert code == 1 and "-> 302" in buf.getvalue()
	assert hits == [("/v1/default/banks/alpha/memories", "Bearer k")]


def test_operation_ids():
	assert im.operation_ids(b'{"operation_id": "abc-1"}') == ["abc-1"]
	assert im.operation_ids(b'{"operation_ids": ["a", "b c", 3], "x": {"operation_id": "d"}}') == ["a", "d"]
	assert im.operation_ids(b"not json") == []


def test_snapshot_uses_backup_api_and_leaves_source_alone(world, monkeypatch):
	db = world["root"] / "pilot-k2j3" / "mnemopi.db"
	calls = []
	real_connect = sqlite3.connect

	def spy(target, *args, **kwargs):
		calls.append(str(target))
		return real_connect(target, *args, **kwargs)

	monkeypatch.setattr(im.sqlite3, "connect", spy)
	rows = im.read_tables(db)
	assert {r["id"] for r in rows} == {"p1", "pe"}
	assert calls[0] == f"{db.resolve().as_uri()}?mode=ro"
	assert all(Path(c).name != "mnemopi.db-wal" for c in calls)


def test_now_is_injectable_for_expiry(world):
	rows, _ = im.collect(
		world["root"],
		world["home"],
		BANKS,
		fake_resolver,
		fake_redact,
		fake_scan,
		now=dt.datetime(1999, 1, 1, tzinfo=dt.timezone.utc),
	)
	assert not any(r.expired for r in rows)


def test_real_redactor_and_scanner(world):
	blob = "Zq8vN3xK7pL2mR9tY4wB6cH1jF5gD0sAuE"
	conn = make_bank(
		world["root"],
		"ui-blob",
		working=[{"id": "z1", "content": f"left in prose {blob} here", "meta": {"cwd": str(world["en"])}}],
	)
	conn.close()
	buf = io.StringIO()
	code = im.main(
		[
			"--config",
			str(world["config"]),
			"--root",
			str(world["root"]),
			"--overlay-dir",
			str(world["overlays"]),
		],
		resolver=fake_resolver,
		home=world["home"],
		out=buf,
	)
	text = buf.getvalue()
	assert code == 0 and SENTINEL not in text and blob not in text
	assert "residual:\tui-blob\tworking_memory\tz1\thigh-entropy\tcontent:" in text
	residual_rows = {line.split("\t")[1] for line in text.splitlines() if line.startswith("residual:\t")}
	assert residual_rows == {"ui-blob"}


SHARE = ("https://share.example.com/doc/", "https://share.example.com/docs/")
SHARE_ID = "a7Kq9Zx2Lm4Np8Rt6Vw3Yb5Hc1Jd0Fg8s"


def test_allow_listed_link_ids_are_not_residual():
	from omp_hindsight_guard.redact import residual_findings

	allowed = f"see https://share.example.com/doc/{SHARE_ID} for the mockup"
	assert residual_findings(allowed)  # the plain scanner (and the proxy) still flag it
	assert im.import_scan(allowed, residual_findings, SHARE) == []
	assert (
		im.import_scan(f"see https://share.example.com/docs/{SHARE_ID}/v2 ok", residual_findings, SHARE) == []
	)
	# Nothing is allowed unless banks.json lists the prefix.
	assert [k for k, _ in im.import_scan(allowed, residual_findings)] == ["high-entropy"]
	assert [k for k, _ in im.import_scan(allowed, residual_findings, ())] == ["high-entropy"]
	elsewhere = f"link id {SHARE_ID} pasted alone"
	assert [k for k, _ in im.import_scan(elsewhere, residual_findings, SHARE)] == ["high-entropy"]
	other_host = f"see https://example.com/doc/{SHARE_ID} for the mockup"
	assert [k for k, _ in im.import_scan(other_host, residual_findings, SHARE)] == ["high-entropy"]
	lookalike = f"see https://share.example.com.evil.example/doc/{SHARE_ID} ok"
	assert [k for k, _ in im.import_scan(lookalike, residual_findings, SHARE)] == ["high-entropy"]
	both = f"https://share.example.com/doc/{SHARE_ID} and later {SHARE_ID}"
	findings = im.import_scan(both, residual_findings, SHARE)
	assert [k for k, _ in findings] == ["high-entropy"] and findings[0][1] > both.index(" and later")


def test_the_allow_list_comes_from_banks_json(world):
	conn = make_bank(
		world["root"],
		"ui-link",
		working=[
			{
				"id": "l1",
				"content": f"mockup at https://share.example.com/doc/{SHARE_ID}",
				"meta": {"cwd": str(world["en"])},
			}
		],
	)
	conn.close()

	def dry_run():
		buf = io.StringIO()
		code = im.main(
			[
				"--config",
				str(world["config"]),
				"--root",
				str(world["root"]),
				"--state-dir",
				str(world["state"]),
			],
			resolver=fake_resolver,
			home=world["home"],
			out=buf,
		)
		return code, buf.getvalue()

	code, text = dry_run()
	assert code == 0 and "residual:\tui-link\tworking_memory\tl1\thigh-entropy" in text
	write_banks_json(world["config"], allow_link_prefixes=["https://share.example.com/doc/"])
	code, text = dry_run()
	assert code == 0 and "ui-link" in text and "residual:\tui-link" not in text and SHARE_ID not in text


def test_send_refuses_an_overlay_whose_bank_id_differs(world):
	"""L10(c): an overlay for another bank must not receive this bank's items."""
	write_overlays(world["overlays"])
	path = world["overlays"] / "alpha.yml"
	path.write_text(path.read_text().replace("bankId: alpha", "bankId: beta"))
	path.chmod(0o600)
	opener = FakeOpener()
	code, _ = run_main(world, "--send", "--confirm", dry_digest(world), opener=opener)
	assert code == 2 and opener.requests == []
	assert not (world["state"] / im.LEDGER_NAME).exists()


def test_unattended_quarantines_residual_documents_and_exports_only_clean(world):
	write_overlays(world["overlays"])
	conn = make_bank(
		world["root"],
		"unsafe-fixture",
		working=[
			{"id": "a", "content": "shared clean content", "meta": {"cwd": str(world["en"])}},
			{
				"id": "b",
				"content": "shared clean content",
				"source": MARK,
				"meta": {"cwd": str(world["en"])},
			},
		],
	)
	conn.close()
	opener = FakeOpener()
	code, text = run_main(world, "--unattended", opener=opener)
	assert code == im.EXIT_QUARANTINE
	assert "quarantined=1" in text
	assert all(
		"shared clean content" not in r.data.decode() and MARK not in r.data.decode() for r in opener.requests
	)
	(summary,) = [world["state"] / "last-run.json"]
	counts = json.loads(summary.read_text())
	assert counts == {"sent": 4, "quarantined": 1, "pending": 0}
	assert stat.S_IMODE(summary.stat().st_mode) == 0o600
	directory = world["state"] / "quarantine"
	assert stat.S_IMODE(directory.stat().st_mode) == 0o700
	(quarantine,) = directory.glob("*.json")
	assert stat.S_IMODE(quarantine.stat().st_mode) == 0o600
	raw = quarantine.read_text()
	assert MARK not in raw and "shared clean content" not in raw and "unsafe-fixture" not in raw
	entries = json.loads(raw)["rows"]
	assert len(entries) == 2 and any(row["findings"] for row in entries)
	(export,) = (world["state"] / "exports").glob("*.jsonl")
	assert stat.S_IMODE(export.stat().st_mode) == 0o600
	assert MARK not in export.read_text() and "shared clean content" not in export.read_text()
	repeat = FakeOpener()
	code, _ = run_main(world, "--unattended", opener=repeat)
	assert code == im.EXIT_QUARANTINE and repeat.requests == []
	assert json.loads(summary.read_text()) == {"sent": 0, "quarantined": 1, "pending": 0}
	conn = sqlite3.connect(world["root"] / "unsafe-fixture" / "mnemopi.db")
	conn.execute("UPDATE working_memory SET source = 'fixed' WHERE id = 'b'")
	conn.commit()
	conn.close()
	released = FakeOpener()
	code, _ = run_main(world, "--unattended", opener=released)
	assert code == 0 and len(sent_ids(released)) == 1
	assert json.loads(summary.read_text()) == {"sent": 1, "quarantined": 0, "pending": 0}


def test_unattended_quarantines_conflicts_without_blocking_other_documents(world):
	write_overlays(world["overlays"])
	seed_ledger(
		world,
		im.Ledger(
			sources={
				"webapp-3tntylzrz3coh:w:a5": "alpha",
				"other-zzz:w:o1": "alpha",
			}
		),
	)
	opener = FakeOpener()
	code, _ = run_main(world, "--unattended", opener=opener)
	assert code == im.EXIT_QUARANTINE
	assert len(sent_ids(opener)) == 3
	assert all("w:a5" not in ident for ident in sent_ids(opener))
	summary = json.loads((world["state"] / "last-run.json").read_text())
	assert summary == {"sent": 3, "quarantined": 2, "pending": 0}
	(quarantine,) = (world["state"] / "quarantine").glob("*.json")
	rows = json.loads(quarantine.read_text())["rows"]
	assert {finding["kind"] for row in rows for finding in row["findings"]} == {
		"ledger-source",
		"ledger-unrouted",
	}


def test_unattended_busy_and_failure_cannot_report_success(world):
	write_overlays(world["overlays"])
	ledger_path = world["state"] / im.LEDGER_NAME
	with im.ledger_lock(ledger_path):
		opener = FakeOpener()
		code, _ = run_main(world, "--unattended", opener=opener)
		assert code == im.EXIT_BUSY and opener.requests == []
		assert not (world["state"] / "last-run.json").exists()
	opener = FakeOpener([422])
	code, _ = run_main(world, "--unattended", opener=opener)
	assert code == 1
	assert json.loads((world["state"] / "last-run.json").read_text()) == {
		"sent": 0,
		"quarantined": 0,
		"pending": 0,
	}


def test_unattended_reconciles_before_retrying_pending_documents(world):
	write_overlays(world["overlays"])
	first = FakeOpener(op_status="processing")
	code, _ = run_main(world, "--unattended", opener=first)
	assert code == 0
	assert json.loads((world["state"] / "last-run.json").read_text())["pending"] == 4
	second = FakeOpener(op_status="completed")
	code, _ = run_main(world, "--unattended", opener=second)
	assert code == 0 and second.requests == [] and second.gets
	assert json.loads((world["state"] / "last-run.json").read_text()) == {
		"sent": 0,
		"quarantined": 0,
		"pending": 0,
	}


def test_since_uses_creation_time_and_fails_closed_on_missing_or_invalid(world):
	write_overlays(world["overlays"])
	conn = make_bank(
		world["root"],
		"cutoff-fixture",
		working=[
			{
				"id": "old",
				"content": "old",
				"created_at": "2026-01-01T00:00:00Z",
				"timestamp": "2027-01-01T00:00:00Z",
				"meta": {"cwd": str(world["en"])},
			},
			{
				"id": "equal",
				"content": "equal",
				"created_at": "2026-06-01T00:00:00Z",
				"meta": {"cwd": str(world["en"])},
			},
			{
				"id": "new",
				"content": "new",
				"created_at": "2026-06-01T01:00:00+01:00",
				"meta": {"cwd": str(world["en"])},
			},
			{"id": "unknown", "content": "unknown", "meta": {"cwd": str(world["en"])}},
			{
				"id": "invalid",
				"content": "invalid",
				"created_at": "invalid",
				"timestamp": "2027-01-01T00:00:00Z",
				"meta": {"cwd": str(world["en"])},
			},
		],
	)
	conn.close()
	opener = FakeOpener()
	code, _ = run_main(world, "--unattended", "--since", "2026-06-01T00:00:00Z", opener=opener)
	assert code == 0
	ids = sent_ids(opener)
	assert any(ident.endswith(":w:equal") for ident in ids)
	assert any(ident.endswith(":w:new") for ident in ids)
	assert not any(ident.endswith((":w:old", ":w:unknown", ":w:invalid")) for ident in ids)
	with pytest.raises(SystemExit):
		run_main(world, "--unattended", "--since", "not-a-time")


def test_unattended_import_with_no_proxy_upstream_key(world):
	config = json.loads(world["config"].read_text())
	del config["proxy"]["upstream_key_file"]
	world["config"].write_text(json.dumps(config))
	write_overlays(world["overlays"])
	opener = FakeOpener()
	code, _ = run_main(world, "--unattended", opener=opener)
	assert code == 0 and len(sent_ids(opener)) == 4


def test_unattended_unknown_send_stays_reserved(world):
	write_overlays(world["overlays"])
	opener = FakeOpener([urllib.error.URLError("unavailable")])
	code, _ = run_main(world, "--unattended", opener=opener)
	assert code == 1
	summary = json.loads((world["state"] / "last-run.json").read_text())
	assert summary["sent"] == 0 and summary["pending"] > 0
	ledger = im.load_ledger(world["state"] / im.LEDGER_NAME)
	assert len(ledger.pending) == summary["pending"]
