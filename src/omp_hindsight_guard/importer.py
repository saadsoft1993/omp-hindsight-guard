"""Import mnemopi working and episodic memories into the Hindsight banks (a one-time migration).

Reads every `<label>-<hash>/mnemopi.db` under the mnemopi banks root through a read-only online backup, routes
each row by its cwd with the roots in banks.json (routing.py; the shell hooks read the same table), tags it
`project:<name>`, redacts it with the proxy's own code, scans what is left for residual secrets and dedupes
identical content within a bank.

Not sent: rows outside every bank root (`skip`), rows without a cwd whose mnemopi bank's cwd rows do not all
route to one bank (`review`, unless --include-review), superseded or expired rows (unless
--include-superseded) and --exclude-label labels.

Dry run by default: prints ids, routing, lengths and redaction/residual counts (never contents) and a digest of
the exact items to send. `--send --confirm <digest>` writes those items to a 0600 file, refuses on residual
findings or on rows the ledger says went to another bank, then posts each batch with its bank's overlay key
and records it in the ledger. `--only-new` limits the items to documents with a row not yet in the ledger with
the same bank and content; `--count-unsynced` only prints `unsynced=<n>`, the number of such rows.
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import dataclasses
import datetime as dt
import fcntl
import functools
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import quote

from omp_hindsight_guard import routing
from omp_hindsight_guard._yaml import MissingDependency
from omp_hindsight_guard.config import (
	ConfigError,
	default_config_path,
	load_config,
	makedirs_private,
	overlay_dir,
	state_dir,
)
from omp_hindsight_guard.overlays import read_overlay

LEDGER_NAME = "import-ledger.json"
TABLES = {"working_memory": "w", "episodic_memory": "e"}
COLUMNS = (
	"id",
	"content",
	"source",
	"timestamp",
	"created_at",
	"session_id",
	"importance",
	"metadata_json",
	"superseded_by",
	"valid_until",
)
BATCH_SIZE = 16
TIMEOUT = 60
MAX_RESPONSE = 1 << 20
# A document read-back carries the stored text (up to 1,000,000 characters, so up to 4 MB as UTF-8 and more with JSON
# escapes) beside its metadata.
MAX_DOCUMENT_RESPONSE = 16 << 20
SKIP_REASONS = (
	"skip",
	"review",
	"excluded-label",
	"superseded",
	"expired",
	"empty",
	"before-since",
	"unknown-time",
)
# Characters the proxy accepts in document ids and tags.
_UNSAFE_IDENT = re.compile(r"[^A-Za-z0-9:_.\-/@ ]")
# A document id must be readable back through the proxy, which takes one path segment of these characters only.
_UNSAFE_DOC_ID = re.compile(r"[^A-Za-z0-9:_.\-@]")
_OPERATION_ID = re.compile(r"[A-Za-z0-9_.:\-]{1,100}")
_LINK_ID = r"([A-Za-z0-9_-]{8,128})(?![A-Za-z0-9_-])"


@functools.lru_cache(maxsize=8)
def _link_pattern(prefixes: tuple[str, ...]) -> re.Pattern[str] | None:
	if not prefixes:
		return None
	return re.compile("(?:" + "|".join(re.escape(p) for p in prefixes) + ")" + _LINK_ID)


def import_scan(text: str, scan: Scanner, link_prefixes: Sequence[str] = ()) -> list[tuple[str, int]]:
	"""`scan` with the id after each allow-listed link prefix blanked out (same length, so offsets hold).

	banks.json `import.allow_link_prefixes` names URL prefixes whose id segment is a public share id rather
	than a secret. Only an exact prefix counts, and only for this import's residual scan; the proxy is unchanged.
	"""
	pattern = _link_pattern(tuple(link_prefixes))
	if pattern is None:
		return scan(text)
	return scan(pattern.sub(lambda m: m.group(0)[: m.start(1) - m.start(0)] + "x" * len(m.group(1)), text))


EXIT_LEDGER = 3
EXIT_RESIDUAL = 4
EXIT_CONFIRM = 5
EXIT_BUSY = 6
EXIT_QUARANTINE = 7
# Statuses of GET /v1/default/banks/{bank}/operations/{id} (hindsight-api 1.2.0, OperationStatusResponse). Only
# `completed` is success; `failed` and `cancelled` mean the operation did not finish (the document may still have
# been created); `pending` and `processing` are open; `not_found` is a completed operation the server has pruned
# (HINDSIGHT_API_OPERATION_RETENTION_DAYS > 0).
OPERATION_DONE = frozenset({"completed"})
OPERATION_FAILED = frozenset({"failed", "cancelled"})
OPERATION_OPEN = frozenset({"pending", "processing"})
OPERATION_PRUNED = "not_found"
OPERATION_TERMINAL = OPERATION_DONE | OPERATION_FAILED | {OPERATION_PRUNED}
OPERATION_STATES = OPERATION_TERMINAL | OPERATION_OPEN
# HTTP statuses the server (or the proxy) answers before it has stored anything: validation, authentication,
# routing and size refusals. A 5xx (a 501 included: the proxy forwards the server's own), a 408 or a redirect proves nothing (the write may have happened and the
# connection died), so those keep the reservation.
PRE_WRITE_REFUSALS = frozenset({400, 401, 403, 404, 405, 411, 413, 414, 415, 422, 429, 431})

Redactor = Callable[[str], "tuple[str, collections.Counter[str]]"]
Scanner = Callable[[str], "list[tuple[str, int]]"]
Resolver = Callable[[Path], "Path | None"]


@dataclasses.dataclass
class Row:
	label: str
	table: str
	id: str
	bank: str | None
	tag: str
	content: str
	source: str | None
	session_id: str | None
	importance: str | None
	timestamp: str | None
	superseded: bool
	expired: bool
	redactions: collections.Counter[str]
	has_cwd: bool = True
	review: bool = False
	missing_cwd: bool = False
	residual: list[tuple[str, str, int]] = dataclasses.field(default_factory=list)
	created: dt.datetime | None = None

	@property
	def key(self) -> tuple[str, str, str]:
		return (self.label, self.table, self.id)

	@property
	def source_key(self) -> str:
		"""`label:w:id` while neither label nor id contains a colon (then it parses one way only); otherwise
		`@` and the SHA-256 of the exact [label, table, id] list, which no plain key (always two colons) can equal."""
		if ":" not in self.label and ":" not in self.id:
			return f"{self.label}:{TABLES[self.table]}:{self.id}"
		return "@" + hashlib.sha256(json.dumps([self.label, self.table, self.id]).encode("utf-8")).hexdigest()


@dataclasses.dataclass
class Doc:
	row: Row
	tags: list[str]
	merged: int
	members: list[Row] = dataclasses.field(default_factory=list)
	document_id: str | None = None

	@property
	def sha(self) -> str:
		return content_hash(self.row.content)


@dataclasses.dataclass
class Ledger:
	"""What earlier runs sent: document_id -> bank/sha, content sha -> {bank: document_id}, source row -> bank.

	`pending` holds what was reserved or accepted but not yet confirmed: document_id -> {bank, sha, sources,
	operations}. `failed` holds what the server reported as failed or cancelled (same fields): offered again, but
	only to the same bank, because a failed operation may still have left the document there. Isolation checks
	see pending and failed entries as if they were confirmed (the server may have them); `synced` and
	`--only-new` do not (the server may never have finished them). An entry leaves `pending` only by being
	confirmed, by a refusal the server makes before writing anything (HTTP 4xx), or by `--drop-unknown`."""

	documents: dict[str, dict[str, str]] = dataclasses.field(default_factory=dict)
	contents: dict[str, dict[str, str]] = dataclasses.field(default_factory=dict)
	sources: dict[str, str] = dataclasses.field(default_factory=dict)
	pending: dict[str, dict[str, Any]] = dataclasses.field(default_factory=dict)
	failed: dict[str, dict[str, Any]] = dataclasses.field(default_factory=dict)
	store: str = ""  # which mnemopi root this ledger belongs to: row ids are only unique within one


Request = tuple[str, tuple[str, ...], list[Doc]]


def label_base(label: str) -> str:
	"""`customer-frontend-3tntylzrz3coh` -> `customer-frontend`."""
	return label.rsplit("-", 1)[0] if "-" in label else label


def safe_ident(text: str) -> str:
	return _UNSAFE_IDENT.sub("_", text)[:200]


def git_primary_root(cwd: Path) -> Path | None:
	"""Primary checkout root of the repo containing cwd (worktrees map to their main checkout)."""
	try:
		proc = subprocess.run(
			["git", "-C", str(cwd), "rev-parse", "--path-format=absolute", "--git-common-dir"],
			capture_output=True,
			text=True,
			timeout=10,
			check=False,
		)
	except (OSError, subprocess.SubprocessError):
		return None
	common = proc.stdout.strip()
	if proc.returncode != 0 or not common:
		return None
	path = Path(common)
	return path.parent if path.name == ".git" else path


def project_tag(cwd: str | None, label: str, resolver: Resolver) -> str:
	name = label_base(label)
	if cwd:
		path = Path(cwd)
		root = resolver(path) if path.is_dir() else None
		if root is not None and root.name:
			name = root.name
		elif path.name:
			name = path.name
	return safe_ident(f"project:{name.lower()}")


def label_bank(label: str, banks: routing.Banks) -> str | None:
	"""Bank whose root directory has the label's name (`webapp-39wp...` -> webapp), if exactly one."""
	base = label_base(label).casefold()
	found = {bank for bank, root in banks if Path(root).name.casefold() == base}
	return found.pop() if len(found) == 1 else None


def parse_time(value: Any) -> dt.datetime | None:
	"""Epoch seconds/milliseconds or ISO-8601 text -> aware UTC datetime; None if unusable."""
	if value is None or value == "":
		return None
	if isinstance(value, str):
		text = value.strip()
		try:
			value = float(text)
		except ValueError:
			if text.endswith(("Z", "z")):
				text = text[:-1] + "+00:00"
			try:
				parsed = dt.datetime.fromisoformat(text)
			except ValueError:
				return None
			return parsed.replace(tzinfo=dt.timezone.utc) if parsed.tzinfo is None else parsed
	if isinstance(value, int | float) and not isinstance(value, bool):
		seconds = float(value) / 1000 if abs(value) > 1e11 else float(value)
		try:
			return dt.datetime.fromtimestamp(seconds, dt.timezone.utc)
		except (OverflowError, OSError, ValueError):
			return None
	return None


def iso(moment: dt.datetime) -> str:
	return moment.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def read_tables(db: Path) -> list[dict[str, Any]]:
	"""All rows of both tables, from a private snapshot taken with SQLite's online backup of a read-only handle."""
	rows: list[dict[str, Any]] = []
	with tempfile.TemporaryDirectory(prefix="mnemopi-import-") as tmp:
		os.chmod(tmp, 0o700)
		copy = Path(tmp) / "snapshot.db"
		src = sqlite3.connect(f"{db.resolve().as_uri()}?mode=ro", uri=True)
		try:
			dst = sqlite3.connect(copy)
			try:
				src.backup(dst)
			finally:
				dst.close()
		finally:
			src.close()
		conn = sqlite3.connect(f"{copy.as_uri()}?mode=ro", uri=True)
		try:
			for table in TABLES:
				present = {r[1] for r in conn.execute(f"PRAGMA table_info('{table}')")}
				if not present:
					continue
				select = ", ".join(c if c in present else f"NULL AS {c}" for c in COLUMNS)
				cursor = conn.execute(f"SELECT {select} FROM {table}")
				for values in cursor:
					rows.append({"table": table, **dict(zip(COLUMNS, values, strict=True))})
		finally:
			conn.close()
	return rows


def text_or_none(value: Any) -> str | None:
	return None if value is None else str(value)


def scan_row(row: Row, scan: Scanner) -> None:
	"""Replace findings with a scan of the row's current, redacted fields."""
	row.residual = [
		(field, kind, offset)
		for field in ("content", "source", "session_id", "importance", "tag")
		if (text := getattr(row, field))
		for kind, offset in scan(text)
	]


def build_row(
	label: str,
	raw: dict[str, Any],
	home: Path,
	banks: routing.Banks,
	resolver: Resolver,
	redact: Redactor,
	scan: Scanner,
	now: dt.datetime,
) -> Row:
	try:
		meta = json.loads(raw["metadata_json"] or "{}")
	except (TypeError, ValueError):
		meta = {}
	cwd = meta.get("cwd") if isinstance(meta, dict) else None
	cwd = cwd if isinstance(cwd, str) and cwd else None
	counts: collections.Counter[str] = collections.Counter()

	def clean(value: Any) -> str | None:
		text = text_or_none(value)
		if text is None:
			return None
		redacted, found = redact(text)
		counts.update(found)
		return redacted

	route = routing.route(cwd, banks, home) if cwd else routing.Route(None, False)
	moment = parse_time(raw["created_at"]) or parse_time(raw["timestamp"])
	valid_until = parse_time(raw["valid_until"])
	importance = raw["importance"]
	row = Row(
		label=label,
		table=raw["table"],
		id=str(raw["id"]),
		bank=route.bank,
		tag=project_tag(cwd, label, resolver),
		content=clean(raw["content"]) or "",
		source=clean(raw["source"]),
		session_id=clean(raw["session_id"]),
		importance=clean(importance),
		timestamp=iso(moment) if moment else None,
		created=parse_time(raw["created_at"] if raw["created_at"] not in (None, "") else raw["timestamp"]),
		superseded=bool(raw["superseded_by"]),
		expired=valid_until is not None and valid_until < now,
		redactions=counts,
		has_cwd=cwd is not None,
		missing_cwd=route.missing_cwd,
		review=route.missing_cwd
		and route.bank is not None,  # the folder is gone: only today's roots place it
	)
	scan_row(row, scan)
	return row


def collect(
	root: Path,
	home: Path,
	banks: routing.Banks,
	resolver: Resolver,
	redact: Redactor,
	scan: Scanner,
	now: dt.datetime | None = None,
) -> tuple[list[Row], int]:
	"""Rows with content from every bank under root, and the number skipped for empty content."""
	now = now or dt.datetime.now(dt.timezone.utc)
	cache: dict[Path, Path | None] = {}

	def cached(path: Path) -> Path | None:
		if path not in cache:
			cache[path] = resolver(path)
		return cache[path]

	rows: list[Row] = []
	empty = 0
	for bank_dir in sorted(p for p in root.iterdir() if (p / "mnemopi.db").is_file()):
		bank_rows = []
		for raw in read_tables(bank_dir / "mnemopi.db"):
			row = build_row(bank_dir.name, raw, home, banks, cached, redact, scan, now)
			if row.content.strip():
				bank_rows.append(row)
			else:
				empty += 1
		inherit_routing(bank_rows, banks)
		for row in bank_rows:
			scan_row(row, scan)
		rows.extend(bank_rows)
	return rows, empty


def inherit_routing(bank_rows: list[Row], banks: routing.Banks) -> None:
	"""Rows without a cwd follow their mnemopi bank's cwd rows when those all route to one (non-None) bank.

	Rows whose folder no longer exists are not evidence (they are routed by a path nobody can check). The
	orphans take that bank and the most common tag among those rows (ties: alphabetically first). Otherwise they
	are flagged for review with a tentative bank: the one bank among the cwd rows, or with no cwd rows at all
	the bank whose root has the label's name; never a default.
	"""
	with_cwd = [r for r in bank_rows if r.has_cwd and not r.missing_cwd]
	orphans = [r for r in bank_rows if not r.has_cwd]
	targets = {r.bank for r in with_cwd}
	if len(targets) == 1 and None not in targets:
		tags = collections.Counter(r.tag for r in with_cwd)
		tag = min(tags, key=lambda t: (-tags[t], t))
		for row in orphans:
			row.bank, row.tag = next(iter(targets)), tag
		return
	known = targets - {None}
	for row in orphans:
		if with_cwd:
			row.bank = next(iter(known)) if len(known) == 1 else None
		else:
			row.bank = label_bank(row.label, banks)
		row.review = True


def skip_reason(
	row: Row,
	include_review: bool,
	include_superseded: bool,
	exclude: Sequence[str],
	since: dt.datetime | None = None,
) -> str | None:
	if since is not None:
		if row.created is None:
			return "unknown-time"
		if row.created < since:
			return "before-since"
	if row.bank is None and not row.review:
		return "skip"
	base = label_base(row.label).casefold()
	if any(base.startswith(prefix.casefold()) for prefix in exclude):
		return "excluded-label"
	if row.review and not include_review:
		return "review"
	if row.bank is None:
		return "skip"
	if not include_superseded:
		if row.superseded:
			return "superseded"
		if row.expired:
			return "expired"
	return None


def select(
	rows: Iterable[Row],
	include_review: bool,
	include_superseded: bool,
	exclude: Sequence[str],
	since: dt.datetime | None = None,
) -> tuple[list[Row], list[tuple[Row, str]]]:
	"""Rows to send, and the others with the reason they are not sent."""
	chosen, skipped = [], []
	for row in rows:
		reason = skip_reason(row, include_review, include_superseded, exclude, since)
		if reason is None:
			chosen.append(row)
		else:
			skipped.append((row, reason))
	return chosen, skipped


def content_hash(text: str) -> str:
	return hashlib.sha256(text.encode("utf-8")).hexdigest()


def dedupe(rows: Iterable[Row]) -> list[Doc]:
	"""One document per (bank, sha256 of redacted content): lowest (label, table, id) wins, tags unioned."""
	groups: dict[tuple[str | None, str], list[Row]] = {}
	for row in rows:
		groups.setdefault((row.bank, content_hash(row.content)), []).append(row)
	docs = []
	for members in groups.values():
		members.sort(key=lambda r: r.key)
		docs.append(Doc(members[0], sorted({m.tag for m in members}), len(members), members))
	docs.sort(key=lambda d: (d.row.bank or "", d.row.key))
	return docs


def default_document_id(row: Row) -> str:
	return document_id_for(("mnemopi", row.bank or "", row.label, TABLES[row.table], row.id))


_HASHED_ID = re.compile(r"@h[0-9a-f]{64}$")


def document_id_for(parts: Sequence[str]) -> str:
	"""A document id the proxy can read back (letters, digits and `: _ . - @`, no `..`, at most 200 characters), built
	from the source identity [namespace, bank, label, table, row id].

	It is `ns:bank:label:table:id` as it stands when that is already readable, short, free of colons inside
	label and id (the one ambiguity of the readable form: `proj:w:7` + `8` and `proj` + `7:w:8` read alike) and does
	not end like a hashed id. Otherwise it is a readable prefix plus `@h` and the full SHA-256 of the JSON of the exact
	parts. Distinct identities therefore get distinct ids except through a SHA-256 collision, and a readable id
	can never equal a hashed one."""
	identity = ":".join(parts)
	plain = re.sub(r"\.{2,}", "_", _UNSAFE_DOC_ID.sub("_", identity))
	ambiguous = any(":" in part for part in parts[2:])
	if plain == identity and not ambiguous and len(identity) <= 120 and not _HASHED_ID.search(identity):
		return identity
	digest = hashlib.sha256(json.dumps(list(parts)).encode("utf-8")).hexdigest()
	return f"{plain[:100]}@h{digest}"


def load_ledger(path: Path) -> Ledger:
	if not path.exists():
		return Ledger()
	data = json.loads(path.read_text())
	if not isinstance(data, dict):
		raise ValueError(f"{path}: not a ledger")
	ledger = Ledger(
		data.get("documents", {}),
		data.get("contents", {}),
		data.get("sources", {}),
		data.get("pending", {}),
		data.get("failed", {}),
		str(data.get("store", "")),
	)
	if not all(
		isinstance(v, dict)
		for v in (ledger.documents, ledger.contents, ledger.sources, ledger.pending, ledger.failed)
	):
		raise ValueError(f"{path}: not a ledger")
	return ledger


def save_ledger(path: Path, ledger: Ledger) -> None:
	"""Atomic 0600 write: temp file in the same directory, then rename."""
	makedirs_private(path.parent)
	fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
	try:
		os.fchmod(fd, 0o600)
		with os.fdopen(fd, "w") as fh:
			json.dump(dataclasses.asdict(ledger), fh, sort_keys=True, indent=1)
			fh.flush()
			os.fsync(fh.fileno())
		os.replace(tmp, path)
	except BaseException:
		Path(tmp).unlink(missing_ok=True)
		raise


class LedgerBusy(RuntimeError):
	"""Another import holds the ledger lock."""


@contextlib.contextmanager
def ledger_lock(path: Path):
	"""Hold an exclusive lock on the ledger for the whole run: two imports sharing a ledger are serialised, so
	the second one checks against what the first one recorded (a plain atomic replace would lose updates)."""
	makedirs_private(path.parent)
	lock_path = path.with_name(path.name + ".lock")
	fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
	try:
		try:
			fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
		except OSError:
			raise LedgerBusy(str(lock_path)) from None
		yield
	finally:
		os.close(fd)


def doc_id_of(doc: Doc) -> str:
	return doc.document_id or default_document_id(doc.row)


def _commit(ledger: Ledger, doc_id: str, bank: str, sha: str, sources: Iterable[str]) -> None:
	"""Confirmed: the document is on the server in this bank with this content."""
	old = ledger.documents.get(doc_id)
	if old is not None and old.get("sha") != sha:
		# The document now holds other content: the old content no longer maps to it.
		stale = ledger.contents.get(old.get("sha", ""), {})
		if stale.get(old.get("bank", "")) == doc_id:
			del stale[old["bank"]]
		if not stale:
			ledger.contents.pop(old.get("sha", ""), None)
	ledger.documents[doc_id] = {"bank": bank, "sha": sha}
	ledger.contents.setdefault(sha, {})[bank] = doc_id
	# Destination history only grows: every source row an earlier attempt at this document (still pending, or
	# recorded as failed) sent to this bank stays tied to it, even if this attempt carried fewer rows.
	history = set(sources)
	for earlier in (ledger.pending.get(doc_id), ledger.failed.get(doc_id)):
		if earlier is not None and earlier.get("bank") == bank:
			history.update(earlier.get("sources", []))
	for source in history:
		ledger.sources[source] = bank
	ledger.pending.pop(doc_id, None)
	ledger.failed.pop(doc_id, None)


def record(ledger: Ledger, docs: Iterable[Doc]) -> None:
	for doc in docs:
		sources = [m.source_key for m in doc.members or [doc.row]]
		_commit(ledger, doc_id_of(doc), doc.row.bank or "", doc.sha, sources)


def reserve(ledger: Ledger, docs: Iterable[Doc]) -> None:
	"""Write the destination down BEFORE sending: a crash after the server accepted a batch must not leave a run
	that could send the same rows somewhere else. A document that is still unresolved is never reserved again:
	that would overwrite the evidence of the first attempt (the caller filters them out with `unresolved`)."""
	for doc in docs:
		doc_id = doc_id_of(doc)
		if doc_id in ledger.pending:
			raise ValueError(f"{doc_id} is still unresolved; reconcile before sending it again")
		sources = [m.source_key for m in doc.members or [doc.row]]
		earlier = ledger.failed.get(doc_id)
		if earlier is not None and earlier.get("bank") == (doc.row.bank or ""):
			sources = sorted(
				set(sources) | set(earlier.get("sources", []))
			)  # a retry never narrows the history
		ledger.pending[doc_id] = {
			"bank": doc.row.bank or "",
			"sha": doc.sha,
			"sources": sources,
			"operations": [],
		}


def unresolved(docs: Iterable[Doc], ledger: Ledger) -> tuple[list[Doc], list[Doc]]:
	"""(documents free to send, documents held back): one whose id, or any of whose source rows, belongs to a
	still-unresolved entry waits for `--reconcile` instead of being sent a second time."""
	held_sources = {s for entry in ledger.pending.values() for s in entry.get("sources", [])}
	free: list[Doc] = []
	held: list[Doc] = []
	for doc in docs:
		sources = {m.source_key for m in doc.members or [doc.row]}
		(held if doc_id_of(doc) in ledger.pending or sources & held_sources else free).append(doc)
	return free, held


def attach_operations(ledger: Ledger, docs: Iterable[Doc], operations: Sequence[str]) -> None:
	for doc in docs:
		entry = ledger.pending.get(doc_id_of(doc))
		if entry is not None:
			entry["operations"] = list(operations)


def release(ledger: Ledger, docs: Iterable[Doc]) -> None:
	"""Forget a reservation: only after the server refused the batch before writing anything."""
	for doc in docs:
		ledger.pending.pop(doc_id_of(doc), None)


def synced(row: Row, ledger: Ledger) -> bool:
	"""The ledger confirms this source row in its bank, and its (redacted) content in that bank, and the document
	that holds the content still has it."""
	bank, sha = row.bank or "", content_hash(row.content)
	doc_id = ledger.contents.get(sha, {}).get(bank)
	document = ledger.documents.get(doc_id) if doc_id else None
	return (
		ledger.sources.get(row.source_key) == bank
		and document is not None
		and document.get("sha") == sha
		and document.get("bank") == bank
	)


def effective_ledger(ledger: Ledger) -> Ledger:
	"""The ledger as isolation checks must see it: confirmed entries plus everything reserved or accepted but not
	yet confirmed."""
	documents = {k: dict(v) for k, v in ledger.documents.items()}
	contents = {s: dict(b) for s, b in ledger.contents.items()}
	sources = dict(ledger.sources)
	for entries in (ledger.failed, ledger.pending):
		for doc_id, entry in entries.items():
			documents.setdefault(doc_id, {"bank": entry["bank"], "sha": entry["sha"]})
			contents.setdefault(entry["sha"], {}).setdefault(entry["bank"], doc_id)
			for source in entry.get("sources", []):
				sources.setdefault(source, entry["bank"])
	return Ledger(documents, contents, sources)


def content_copies(docs: Iterable[Doc], ledger: Ledger) -> list[tuple[Row, list[str]]]:
	"""Documents whose content is also in ANOTHER bank, in the ledger or in this same run. Not a conflict: a
	distinct source row in this bank is that row's own memory, routed by its own folder (policy: identical text
	may live in several banks), and a source row that moved banks is refused separately. Listed so a human sees
	every cross-bank copy before sending."""
	docs = list(docs)
	banks: dict[str, set[str]] = collections.defaultdict(set)
	for sha, by_bank in effective_ledger(ledger).contents.items():
		banks[sha].update(by_bank)
	for doc in docs:
		banks[doc.sha].add(doc.row.bank or "")
	found = []
	for doc in docs:
		others = sorted(banks[doc.sha] - {doc.row.bank or ""})
		if others:
			found.append((doc.row, others))
	return found


def apply_ledger(
	docs: list[Doc], ledger: Ledger, skipped: Iterable[tuple[Row, str]] = ()
) -> list[tuple[Row, str, str]]:
	"""Reuse earlier document ids per (content, bank); return (row, earlier bank, why) for cross-bank moves.

	A row sent earlier that now routes to no bank (`skip`) is a move too: its copy stays in the earlier bank.
	Reserved and accepted-but-unconfirmed entries count as sent.
	"""
	ledger = effective_ledger(ledger)
	defaults = collections.Counter(default_document_id(d.row) for d in docs)
	for doc in docs:
		own = default_document_id(doc.row)
		earlier = ledger.contents.get(doc.sha, {}).get(doc.row.bank or "")
		taken = defaults[earlier] - (earlier == own) if earlier else 0
		doc.document_id = earlier if earlier and not taken else own
	conflicts: list[tuple[Row, str, str]] = []
	used = collections.Counter(d.document_id for d in docs)
	for doc in docs:
		bank = doc.row.bank or ""
		for member in doc.members or [doc.row]:
			before = ledger.sources.get(member.source_key)
			if before is not None and before != bank:
				conflicts.append((member, before, "source"))
		previous = ledger.documents.get(doc.document_id or "")
		if previous is not None and previous.get("bank") != bank:
			conflicts.append((doc.row, previous.get("bank", "?"), "document"))
		if used[doc.document_id] > 1:
			conflicts.append((doc.row, bank, "duplicate-id"))
	for row, reason in skipped:
		before = ledger.sources.get(row.source_key)
		if reason == "skip" and before is not None:
			conflicts.append((row, before, "unrouted"))
	return conflicts


def to_item(doc: Doc) -> dict[str, Any]:
	row = doc.row
	metadata = {
		"source": row.source,
		"importance": row.importance,
		"session_id": row.session_id,
		"mnemopi_table": row.table,
		"superseded": "true" if row.superseded else "false",
	}
	item: dict[str, Any] = {
		"content": row.content,
		"context": f"mnemopi import: {row.source or 'unknown'}",
		"document_id": doc.document_id or default_document_id(row),
		"tags": list(doc.tags),
		"metadata": {k: str(v) for k, v in metadata.items() if v is not None},
	}
	if row.timestamp:
		item["timestamp"] = row.timestamp
	return item


def batches(docs: Iterable[Doc]) -> list[Request]:
	"""One request per (bank, tag set), at most BATCH_SIZE documents each, in a stable order."""
	groups: dict[tuple[str, tuple[str, ...]], list[Doc]] = {}
	for doc in docs:
		groups.setdefault((doc.row.bank or "", tuple(doc.tags)), []).append(doc)
	out = []
	for (bank, tags), members in sorted(groups.items()):
		for start in range(0, len(members), BATCH_SIZE):
			out.append((bank, tags, members[start : start + BATCH_SIZE]))
	return out


def payload(requests: list[Request]) -> list[dict[str, Any]]:
	return [{"bank": bank, "items": [to_item(d) for d in docs]} for bank, _, docs in requests]


def digest(requests: list[Request]) -> str:
	"""sha256 of the canonical JSON of every item to send, with its bank."""
	canonical = json.dumps(payload(requests), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
	return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def write_redacted(path: Path, requests: list[Request], force: bool) -> None:
	"""JSONL, one `{"bank", "item"}` per line, created 0600; refuses an existing file unless force."""
	makedirs_private(path.parent)
	flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | (os.O_TRUNC if force else os.O_EXCL)
	fd = os.open(path, flags, 0o600)
	os.fchmod(fd, 0o600)
	with os.fdopen(fd, "w") as fh:
		for entry in payload(requests):
			for item in entry["items"]:
				fh.write(
					json.dumps({"bank": entry["bank"], "item": item}, sort_keys=True, ensure_ascii=False)
				)
				fh.write("\n")


def write_quarantine(state: Path, docs: list[Doc], conflicts: list[tuple[Row, str, str]]) -> int:
	"""Record only opaque row identities and finding metadata, never memory content."""
	conflict_by_row: dict[tuple[str, str, str], list[str]] = collections.defaultdict(list)
	for row, _, why in conflicts:
		conflict_by_row[row.key].append(why)
	entries = []
	held_keys = set()
	for doc in docs:
		for row in doc.members or [doc.row]:
			held_keys.add(row.key)
			entries.append(
				{
					"row": "@" + hashlib.sha256(json.dumps(row.key).encode()).hexdigest(),
					"table": row.table,
					"bank": row.bank,
					"findings": [
						{"kind": kind, "field": field, "offset": offset}
						for field, kind, offset in row.residual
					]
					+ [{"kind": "ledger-" + why} for why in conflict_by_row[row.key]],
				}
			)
	extra = 0
	for row, _, why in conflicts:
		if row.key not in held_keys:
			entries.append(
				{
					"row": "@" + hashlib.sha256(json.dumps(row.key).encode()).hexdigest(),
					"table": row.table,
					"bank": row.bank,
					"findings": [{"kind": "ledger-" + why}],
				}
			)
			held_keys.add(row.key)
			extra += 1
	if not entries:
		return 0
	directory = state / "quarantine"
	makedirs_private(directory)
	os.chmod(directory, 0o700)
	stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ-")
	fd, name = tempfile.mkstemp(prefix=stamp, suffix=".json", dir=directory)
	try:
		with os.fdopen(fd, "w") as fh:
			json.dump({"rows": entries}, fh, sort_keys=True)
	except BaseException:
		Path(name).unlink(missing_ok=True)
		raise
	return len(docs) + extra


def write_last_run(state: Path, counts: dict[str, int]) -> None:
	"""Atomically publish a private, counts-only summary."""
	makedirs_private(state)
	fd, name = tempfile.mkstemp(prefix=".last-run.", dir=state)
	try:
		with os.fdopen(fd, "w") as fh:
			json.dump(counts, fh, sort_keys=True)
			fh.flush()
			os.fsync(fh.fileno())
		os.replace(name, state / "last-run.json")
	except BaseException:
		Path(name).unlink(missing_ok=True)
		raise


def fmt_counts(counts: collections.Counter[str]) -> str:
	return ",".join(f"{k}={v}" for k, v in sorted(counts.items()) if v) or "none"


def residual_counts(rows: Iterable[Row]) -> collections.Counter[str]:
	return collections.Counter(kind for row in rows for _, kind, _ in row.residual)


def report(
	rows: list[Row],
	docs: list[Doc],
	skipped: list[tuple[Row, str]],
	empty: int,
	conflicts: list[tuple[Row, str, str]],
	requests: list[Request],
	out: TextIO,
	sync: tuple[int, int],
	notes: Sequence[tuple[Row, list[str]]] = (),
	pending_docs: int = 0,
	ledger: Ledger | None = None,
) -> None:
	reasons = {r.key: reason for r, reason in skipped}
	for row in sorted(rows, key=lambda r: r.key):
		flags = ",".join(f for f, on in (("missing-cwd", row.missing_cwd), ("review", row.review)) if on)
		print(
			f"{row.label}\t{row.table}\t{row.id}\t-> {row.bank or '-'}\t{row.tag}\t"
			f"len={len(row.content)}\tredactions={fmt_counts(row.redactions)}\t"
			f"residual={fmt_counts(residual_counts([row]))}\t{reasons.get(row.key, 'send')}"
			+ (f"\tflags={flags}" if flags else "")
			+ f"\tsha={content_hash(row.content)}\tstate={'synced' if ledger is not None and synced(row, ledger) else 'waiting'}",
			file=out,
		)
	for row in sorted((r for r in rows if r.review), key=lambda r: r.key):
		print(f"review:\t{row.label}\t{row.table}\t{row.id}\t-> {row.bank or '-'}\t{row.tag}", file=out)
	for row, reason in sorted(skipped, key=lambda s: s[0].key):
		print(f"skip:\t{row.label}\t{row.table}\t{row.id}\t{reason}", file=out)
	for row in sorted(rows, key=lambda r: r.key):
		for field, kind, offset in row.residual:
			print(f"residual:\t{row.label}\t{row.table}\t{row.id}\t{kind}\t{field}:{offset}", file=out)
	for row, before, why in conflicts:
		print(
			f"ledger-conflict:\t{row.label}\t{row.table}\t{row.id}\t-> {row.bank or '-'}\t"
			f"earlier={before}\t{why}",
			file=out,
		)
	print("== summary ==", file=out)
	per_source = collections.Counter((r.label, r.table) for r in rows)
	for (label, table), n in sorted(per_source.items()):
		print(f"source\t{label}\t{table}\t{n}", file=out)
	per_target = collections.Counter((d.row.bank, ",".join(d.tags)) for d in docs)
	for (bank, tags), n in sorted(per_target.items()):
		print(f"target\t{bank}\t{tags}\t{n}", file=out)
	total: collections.Counter[str] = collections.Counter()
	for row in rows:
		total.update(row.redactions)
	per_table = collections.Counter(r.table for r in rows)
	sent_rows = [m for d in docs for m in d.members or [d.row]]
	print(
		f"rows={len(rows)} (working_memory={per_table['working_memory']}, "
		f"episodic_memory={per_table['episodic_memory']}) to_send={len(sent_rows)} after_dedupe={len(docs)} "
		f"superseded={sum(r.superseded for r in rows)} expired={sum(r.expired for r in rows)} "
		f"review={sum(r.review for r in rows)} missing_cwd={sum(r.missing_cwd for r in rows)}",
		file=out,
	)
	print(f"already_synced={sync[0]} unsynced={sync[1]}", file=out)
	why = collections.Counter(reason for _, reason in skipped)
	why["empty"] += empty
	print("skipped: " + " ".join(f"{reason}={why[reason]}" for reason in SKIP_REASONS), file=out)
	print(f"redactions: {fmt_counts(total)}", file=out)
	print(f"residual: {fmt_counts(residual_counts(sent_rows))}", file=out)
	print(f"residual_not_sent: {fmt_counts(residual_counts(r for r, _ in skipped))}", file=out)
	for row, banks in sorted(notes, key=lambda n: n[0].key):
		print(
			f"content-also-in:\t{row.label}\t{row.table}\t{row.id}\t-> {row.bank or '-'}\talso-in={','.join(banks)}",
			file=out,
		)
	if pending_docs:
		print(f"pending_operations={pending_docs} (run --reconcile)", file=out)
	print(f"ledger_conflicts={len(conflicts)}", file=out)
	print(f"requests={len(requests)} items={sum(len(d) for _, _, d in requests)}", file=out)
	print(f"digest={digest(requests)}", file=out)


class NoRedirect(urllib.request.HTTPRedirectHandler):
	"""Never follow a redirect: the 3xx surfaces as an HTTPError, so the bearer is never re-sent elsewhere."""

	def redirect_request(self, req, fp, code, msg, headers, newurl):
		return None


def build_opener() -> urllib.request.OpenerDirector:
	return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def operation_ids(body: bytes) -> list[str]:
	"""`operation_id` / `operation_ids` values from a JSON response, id-shaped strings only."""
	try:
		data = json.loads(body)
	except ValueError:
		return []
	found: list[str] = []

	def walk(value: Any) -> None:
		if isinstance(value, dict):
			for key, inner in value.items():
				if key in ("operation_id", "operation_ids"):
					for op in inner if isinstance(inner, list) else [inner]:
						if isinstance(op, str) and _OPERATION_ID.fullmatch(op):
							found.append(op)
				else:
					walk(inner)
		elif isinstance(value, list):
			for inner in value:
				walk(inner)

	walk(data)
	return list(dict.fromkeys(found))  # operation_id repeats the first of operation_ids


class ResponseTooLarge(ValueError):
	"""A reply longer than the limit for it: reported as such, never parsed as if it were complete."""


def _get_json(url: str, token: str, opener: Any, limit: int = MAX_RESPONSE) -> Any:
	"""The JSON body of a GET, read up to `limit` bytes plus one so that an oversized reply is detected instead of
	truncated. HTTP errors propagate as HTTPError, ResponseTooLarge and unparseable bodies as ValueError."""
	req = urllib.request.Request(
		url, method="GET", headers={"Authorization": f"Bearer {token}", "Accept": "application/json"}
	)
	resp = opener.open(req, timeout=TIMEOUT)
	try:
		body = resp.read(limit + 1) if 200 <= resp.status < 300 else b""
	finally:
		resp.close()
	if len(body) > limit:
		raise ResponseTooLarge(f"reply longer than {limit} bytes")
	return json.loads(body)


def operation_state(bank: str, operation: str, overlays: dict[str, tuple[str, str]], opener: Any) -> str:
	"""The server's status for an accepted operation, as one of OPERATION_STATES, or what went wrong:
	`invalid` (HTTP 400: the id is not one the server issued), `error` (any other failure), `unknown` (a status or
	an answer this version does not recognise). Only `completed` ever counts as success."""
	url, token = overlays[bank]
	try:
		data = _get_json(f"{url}/v1/default/banks/{bank}/operations/{operation}", token, opener)
	except urllib.error.HTTPError as err:
		return "invalid" if err.code == 400 else "error"
	except (urllib.error.URLError, OSError, ValueError):
		return "error"
	if not isinstance(data, dict) or data.get("operation_id", operation) != operation:
		return "unknown"
	state = data.get("status")
	state = state.lower() if isinstance(state, str) else ""
	return state if state in OPERATION_STATES else "unknown"


def document_state(
	bank: str, doc_id: str, sha: str, overlays: dict[str, tuple[str, str]], opener: Any
) -> str:
	"""Is the document stored in this bank with the content that was sent? `present` (the server's content hash or
	its stored text hashes to the sent content), `different` (stored, but not this content: overwritten, or changed
	by the server's own sanitising), `absent` (HTTP 404), `too-large` (the reply exceeds MAX_DOCUMENT_RESPONSE) or
	`unreadable`."""
	url, token = overlays[bank]
	try:
		data = _get_json(
			f"{url}/v1/default/banks/{bank}/documents/{quote(doc_id, safe=':@')}",
			token,
			opener,
			MAX_DOCUMENT_RESPONSE,
		)
	except urllib.error.HTTPError as err:
		return "absent" if err.code == 404 else "unreadable"
	except ResponseTooLarge:
		return "too-large"
	except (urllib.error.URLError, OSError, ValueError):
		return "unreadable"
	if not isinstance(data, dict) or data.get("id") != doc_id:
		return "unreadable"
	text = data.get("original_text")
	if data.get("content_hash") == sha or (isinstance(text, str) and content_hash(text) == sha):
		return "present"
	return "different"


def reconcile(
	ledger: Ledger,
	overlays: dict[str, tuple[str, str]],
	opener: Any,
	out: TextIO,
	drop_unknown: bool = False,
) -> tuple[int, int, int, int]:
	"""Settle every reserved or accepted document against the server, once.

	- every operation `completed`: confirmed (synced);
	- any operation still `pending`/`processing`: left alone;
	- otherwise the document itself is read (`document_state`) and decides: stored with the expected content ->
	confirmed, whatever the operations said (a pruned operation reads `not_found`, an answer this version does
	not know reads `unknown`; a reply that carried no operation id has none to ask);
	- every operation `failed`/`cancelled` (or some failed and the document is absent): moved to `failed`, offered
	again, to the same bank only, because a failed operation may still have left the document there;
	- anything else is reported as `unconfirmed` and stays pending. Nothing becomes synced without the server
	saying so, and nothing leaves `pending` silently.
	`drop_unknown` releases the unconfirmed ones and the `failed` records (never an open operation): use it only
	after checking the server yourself, because the document may still be there.
	Returns (confirmed, failed, still pending in the ledger, unconfirmed)."""
	groups: dict[tuple[str, str], list[str]] = {}
	for doc_id, entry in ledger.pending.items():
		for operation in entry.get("operations", []):
			groups.setdefault((entry["bank"], operation), []).append(doc_id)
	states: dict[tuple[str, str], str] = {}
	for bank, operation in sorted(groups):
		state = operation_state(bank, operation, overlays, opener) if bank in overlays else "error"
		states[(bank, operation)] = state
		print(f"operation bank={bank} id={operation} -> {state}", file=out)
	confirmed = failed = unconfirmed = dropped = 0
	for doc_id, entry in list(ledger.pending.items()):
		bank, operations = entry["bank"], entry.get("operations", [])
		got = [states[(bank, op)] for op in operations]
		if any(s in OPERATION_OPEN for s in got):
			continue  # still being processed: nothing to decide yet
		if operations and all(s in OPERATION_DONE for s in got):
			_commit(ledger, doc_id, bank, entry["sha"], entry.get("sources", []))
			confirmed += 1
			continue
		stored = (
			document_state(bank, doc_id, entry["sha"], overlays, opener) if bank in overlays else "unreadable"
		)
		if stored == "present":
			print(
				f"document bank={bank} id={doc_id} -> present ({','.join(sorted(set(got))) or 'no operation'})",
				file=out,
			)
			_commit(ledger, doc_id, bank, entry["sha"], entry.get("sources", []))
			confirmed += 1
		elif operations and (
			all(s in OPERATION_FAILED for s in got)
			or (
				stored == "absent"
				and any(s in OPERATION_FAILED for s in got)
				and all(s in OPERATION_TERMINAL for s in got)
			)
		):
			ledger.pending.pop(doc_id)
			record_failed = {k: entry[k] for k in ("bank", "sha", "sources", "operations") if k in entry}
			before = ledger.failed.get(doc_id)
			if before is not None and before.get("bank") == bank:  # history only grows
				record_failed["sources"] = sorted(
					set(record_failed.get("sources", [])) | set(before.get("sources", []))
				)
			ledger.failed[doc_id] = record_failed
			failed += 1
		elif drop_unknown:
			ledger.pending.pop(doc_id)
			dropped += 1
		else:
			why = ",".join(sorted(set(got))) or "no operation id"
			print(f"unconfirmed bank={bank} id={doc_id} (operations: {why}; document {stored})", file=out)
			unconfirmed += 1
	if drop_unknown and ledger.failed:
		dropped += len(ledger.failed)
		ledger.failed.clear()
	pending = len(ledger.pending)
	print(
		f"operations: confirmed={confirmed} failed={failed} unconfirmed={unconfirmed} dropped={dropped} "
		f"pending={pending - unconfirmed}",
		file=out,
	)
	return confirmed, failed, pending, unconfirmed


def send(
	requests: list[Request],
	overlays: dict[str, tuple[str, str]],
	opener: Any,
	out: TextIO,
	on_success: Callable[[list[Doc]], None] = lambda docs: None,
	*,
	on_reserve: Callable[[list[Doc]], None] | None = None,
	on_accept: Callable[[list[Doc], list[str]], None] | None = None,
	on_reject: Callable[[list[Doc]], None] | None = None,
) -> int:
	"""POST each batch; stop at the first failure (any non-2xx, redirects included). Returns the exit code.

	`on_reserve` runs before each POST, `on_accept(docs, operation ids)` after a 2xx, `on_reject` after a definite
	refusal (an HTTP status). A network error or timeout leaves the reservation in place: the server may have
	taken the batch."""
	for bank, tags, docs in requests:
		url, token = overlays[bank]
		req = urllib.request.Request(
			f"{url}/v1/default/banks/{bank}/memories",
			data=json.dumps({"async": True, "items": [to_item(d) for d in docs]}).encode("utf-8"),
			method="POST",
			headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
		)
		label = f"POST bank={bank} tags={','.join(tags)} items={len(docs)}"
		body = b""
		if on_reserve is not None:
			on_reserve(docs)
		try:
			resp = opener.open(req, timeout=TIMEOUT)
			try:
				status = resp.status
				if 200 <= status < 300:
					body = resp.read(MAX_RESPONSE)
			finally:
				resp.close()
		except urllib.error.HTTPError as err:
			status = err.code
			err.close()
		except (urllib.error.URLError, OSError) as err:
			print(
				f"{label} -> error {type(err).__name__} (outcome unknown; the batch stays reserved)", file=out
			)
			return 1
		if not 200 <= status < 300:
			if status in PRE_WRITE_REFUSALS:
				if on_reject is not None:
					on_reject(docs)
				print(f"{label} -> {status} (refused before anything was stored)", file=out)
			else:  # a 5xx, a redirect, ...: the server (or the proxy in front of it) may have stored the batch
				print(f"{label} -> {status} (outcome unknown; the batch stays reserved)", file=out)
			return 1
		operations = operation_ids(body)
		print(f"{label} -> {status} operations={','.join(operations) or 'none'}", file=out)
		if on_accept is not None:
			on_accept(docs, operations)
		else:
			on_success(docs)
	print(f"sent requests={len(requests)} items={sum(len(d) for _, _, d in requests)}", file=out)
	return 0


def _load_overlays(
	banks: Iterable[str], overlays_path: Path, strict: bool = True
) -> dict[str, tuple[str, str]] | None:
	"""URL and token per bank, each from one validated read that also checks the bank id. Strict: the first
	problem is printed and None returned. Not strict: unusable overlays are skipped."""
	found: dict[str, tuple[str, str]] = {}
	for bank in sorted(set(banks)):
		path = overlays_path / f"{bank}.yml"
		try:
			overlay = read_overlay(path)
			if overlay.bank != bank:  # an overlay for another bank must not receive this bank's items
				raise ValueError(f"{path}: hindsight.bankId is not {bank!r}")
			found[bank] = (overlay.url, overlay.token)
		except (OSError, ValueError, MissingDependency) as err:
			if strict:
				print(f"overlay for {bank}: {type(err).__name__}: {err}", file=sys.stderr)
				return None
	return found


def main(
	argv: list[str] | None = None,
	*,
	resolver: Resolver = git_primary_root,
	redact: Redactor | None = None,
	scan: Scanner | None = None,
	opener: Any = None,
	home: Path | None = None,
	now: dt.datetime | None = None,
	out: TextIO | None = None,
	env: Any = None,
) -> int:
	with contextlib.ExitStack() as stack:
		return _main(
			argv,
			stack,
			resolver=resolver,
			redact=redact,
			scan=scan,
			opener=opener,
			home=home,
			now=now,
			out=out,
			env=env,
		)


def _main(
	argv: list[str] | None,
	stack: contextlib.ExitStack,
	*,
	resolver: Resolver,
	redact: Redactor | None,
	scan: Scanner | None,
	opener: Any,
	home: Path | None,
	now: dt.datetime | None,
	out: TextIO | None,
	env: Any,
) -> int:
	parser = argparse.ArgumentParser(prog="omp-hindsight-guard import", description=__doc__.splitlines()[0])
	parser.add_argument("--config", type=Path, help="banks.json (default: the tool's config directory)")
	parser.add_argument("--send", action="store_true", help="post to Hindsight (default: dry run)")
	parser.add_argument(
		"--unattended", action="store_true", help="send new rows and quarantine unsafe documents"
	)
	parser.add_argument(
		"--since", metavar="ISO_TIME", help="only rows created at or after this time (UTC if naive)"
	)
	parser.add_argument(
		"--confirm", metavar="DIGEST", help="digest printed by the dry run (required by --send)"
	)
	parser.add_argument(
		"--reconcile",
		action="store_true",
		help="check the operations the server accepted earlier; confirmed rows count as synced, failed ones are offered again",
	)
	parser.add_argument(
		"--drop-unknown",
		action="store_true",
		help="with --reconcile: forget every destination still unresolved after the check: reservations whose POST "
		"never returned, unconfirmed documents (pruned, unknown or unreadable) and the failed records, so those rows "
		"may then go to another bank. Never an operation still pending/processing. Check the server first",
	)
	parser.add_argument("--overlay-dir", type=Path, help="default: the tool's overlay directory")
	parser.add_argument("--state-dir", type=Path, help="holds the ledger and the redacted exports")
	parser.add_argument(
		"--root", type=Path, help="mnemopi banks root (default: import.mnemopi_root or omp's)"
	)
	parser.add_argument("--ledger", type=Path, help=f"default: <state-dir>/{LEDGER_NAME}")
	parser.add_argument("--include-review", action="store_true", help="also send rows flagged review")
	parser.add_argument("--include-superseded", action="store_true", help="also send superseded/expired rows")
	parser.add_argument(
		"--exclude-label",
		action="append",
		default=[],
		metavar="LABEL",
		help="skip mnemopi labels with this prefix (adds to import.exclude_labels)",
	)
	parser.add_argument("--write-redacted", type=Path, metavar="FILE", help="write the items as 0600 JSONL")
	parser.add_argument("--force", action="store_true", help="overwrite an existing --write-redacted file")
	parser.add_argument(
		"--only-new",
		action="store_true",
		help="only documents with a row not yet in the ledger with the same bank and content",
	)
	parser.add_argument(
		"--count-unsynced",
		action="store_true",
		help="print only unsynced=<n> (rows to send that the ledger lacks) and exit",
	)
	args = parser.parse_args(argv)
	if args.since is not None:
		try:
			since = dt.datetime.fromisoformat(args.since.replace("Z", "+00:00"))
		except ValueError:
			parser.error("--since must be an ISO-8601 date and time")
		if since.tzinfo is None:
			since = since.replace(tzinfo=dt.timezone.utc)
	else:
		since = None
	if args.unattended and (args.count_unsynced or args.reconcile or args.confirm):
		parser.error("--unattended cannot be combined with --count-unsynced, --reconcile or --confirm")
	if args.unattended:
		args.send = True
		args.only_new = True
	if args.count_unsynced and (args.send or args.write_redacted or args.reconcile):
		parser.error("--count-unsynced takes no --send, --write-redacted or --reconcile")
	if args.reconcile and (args.send or args.write_redacted):
		parser.error("--reconcile takes no --send or --write-redacted")
	if args.drop_unknown and not args.reconcile:
		parser.error("--drop-unknown needs --reconcile")
	out = out or sys.stdout
	env = os.environ if env is None else env
	home = home or Path.home()
	try:
		config = load_config(args.config or default_config_path(env), env)
	except ConfigError as err:
		print(f"config: {err}", file=sys.stderr)
		return 2
	root = (
		args.root or config.importer.mnemopi_root or home / ".omp/agent/memories/mnemopi/banks"
	).expanduser()
	if not args.reconcile and not root.is_dir():
		print(f"no mnemopi banks root at {root}", file=sys.stderr)
		return 2
	if redact is None or scan is None:
		from omp_hindsight_guard.redact import redact_text, residual_findings

		prefixes = config.importer.allow_link_prefixes
		redact = redact or redact_text
		scan = scan or (lambda text: import_scan(text, residual_findings, prefixes))
	if args.count_unsynced:
		# Counting needs the redacted content's hash only: no residual scan, no git lookups for tags.
		scan = lambda text: []  # noqa: E731
		resolver = lambda path: None  # noqa: E731
	overlays_path = (args.overlay_dir or overlay_dir(env, home)).expanduser()
	state = (args.state_dir or state_dir(env, home)).expanduser()
	ledger_path = (args.ledger or state / LEDGER_NAME).expanduser()
	try:
		if args.send or args.reconcile:
			# Held until this run ends: the ledger is read, checked, sent against and written under one lock.
			stack.enter_context(ledger_lock(ledger_path))
		ledger = load_ledger(ledger_path)
	except LedgerBusy as err:
		print(f"refused: another import is using this ledger ({err}); nothing sent", file=out)
		return EXIT_BUSY
	except (OSError, ValueError) as err:
		print(f"ledger: {type(err).__name__}: {err}", file=sys.stderr)
		return 2
	counts = {"sent": 0, "quarantined": 0, "pending": len(ledger.pending)}
	if args.unattended:

		def publish_summary() -> None:
			counts["pending"] = len(ledger.pending)
			write_last_run(state, counts)

		stack.callback(publish_summary)
	real_opener = opener or build_opener()
	if args.reconcile:
		found = _load_overlays({e["bank"] for e in ledger.pending.values()}, overlays_path)
		if found is None:
			return 2
		_, failed, _, unconfirmed = reconcile(ledger, found, real_opener, out, args.drop_unknown)
		save_ledger(ledger_path, ledger)
		return 1 if failed or unconfirmed else 0
	banks = config.routes
	store = hashlib.sha256(os.path.realpath(root).encode("utf-8")).hexdigest()[:16]
	if ledger.store and ledger.store != store:
		print(
			"refused: this ledger belongs to another mnemopi root (row ids are only unique within one store); "
			"use a separate --state-dir or --ledger for each root; nothing sent",
			file=out,
		)
		return EXIT_LEDGER
	ledger.store = store  # recorded with the next save
	previous_failed = previous_unconfirmed = 0
	if args.unattended and ledger.pending:
		found = (
			_load_overlays({e["bank"] for e in ledger.pending.values()}, overlays_path, strict=False) or {}
		)
		_, previous_failed, _, previous_unconfirmed = reconcile(ledger, found, real_opener, out)
		save_ledger(ledger_path, ledger)
	rows, empty = collect(root, home, banks, resolver, redact, scan, now)
	exclude = [*config.importer.exclude_labels, *args.exclude_label]
	chosen, skipped = select(rows, args.include_review, args.include_superseded, exclude, since)
	unsynced = sum(not synced(row, ledger) for row in chosen)
	if args.count_unsynced:
		print(f"unsynced={unsynced}", file=out)
		return 0
	docs = dedupe(chosen)
	conflicts = apply_ledger(docs, ledger, skipped)
	if args.unattended:
		conflict_keys = {row.key for row, _, _ in conflicts}
		quarantined = [
			doc
			for doc in docs
			if any(member.residual or member.key in conflict_keys for member in doc.members or [doc.row])
		]
		counts["quarantined"] = write_quarantine(state, quarantined, conflicts)
		held_docs = {id(doc) for doc in quarantined}
		docs = [doc for doc in docs if id(doc) not in held_docs]
	docs, held = unresolved(docs, ledger)
	if held:  # a second send of these would overwrite the evidence of the first attempt
		print(
			f"held_unresolved={len(held)} (still being settled: run --reconcile, then send again)", file=out
		)
	notes = content_copies(docs, ledger)
	if args.only_new:
		docs = [d for d in docs if not all(synced(m, ledger) for m in d.members or [d.row])]
	requests = batches(docs)
	report(
		rows,
		docs,
		skipped,
		empty,
		conflicts,
		requests,
		out,
		(len(chosen) - unsynced, unsynced),
		notes,
		len(ledger.pending),
		ledger,
	)
	current = digest(requests)

	redacted_path = args.write_redacted
	if not args.send:
		if redacted_path is None:
			return 0
	elif not args.unattended and args.confirm != current:
		print("refused: --send needs --confirm equal to the digest above; nothing sent", file=out)
		return EXIT_CONFIRM
	elif redacted_path is None:
		stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
		redacted_path = state / "exports" / f"hindsight-import-{stamp}.jsonl"
	try:
		write_redacted(redacted_path.expanduser(), requests, args.force)
	except FileExistsError:
		print(f"refused: {redacted_path} exists (use --force); nothing sent", file=sys.stderr)
		return 2
	print(f"redacted items written: {redacted_path}", file=out)
	if not args.send:
		return 0
	if conflicts and not args.unattended:
		print(f"refused: {len(conflicts)} ledger conflict(s) above; nothing sent", file=out)
		return EXIT_LEDGER
	if residual_counts(m for d in docs for m in d.members or [d.row]):
		print("refused: residual findings in items to send; nothing sent", file=out)
		return EXIT_RESIDUAL
	overlays = _load_overlays({bank for bank, _, _ in requests}, overlays_path)
	if overlays is None:
		return 2

	def persist() -> None:
		save_ledger(ledger_path, ledger)

	def on_reserve(sent: list[Doc]) -> None:
		reserve(ledger, sent)
		persist()

	def on_accept(sent: list[Doc], operations: list[str]) -> None:
		counts["sent"] += len(sent)
		# Every request asks for asynchronous processing, so a reply without a usable operation id is not
		# evidence of anything: the reservation stays, and `reconcile` asks the server about the document itself.
		if operations:
			attach_operations(ledger, sent, operations)
		else:
			print(
				"reply carried no usable operation id: the batch stays unconfirmed until the server shows it",
				file=out,
			)
		persist()

	def on_reject(sent: list[Doc]) -> None:
		release(ledger, sent)
		persist()

	code = send(
		requests,
		overlays,
		real_opener,
		out,
		on_reserve=on_reserve,
		on_accept=on_accept,
		on_reject=on_reject,
	)
	# Accepted is not synchronised: ask the server once about every operation this ledger is waiting for.
	others = _load_overlays({e["bank"] for e in ledger.pending.values()}, overlays_path, strict=False) or {}
	_, failed, _, unconfirmed = reconcile(ledger, overlays | others, real_opener, out)
	persist()
	if args.unattended:
		print(
			f"sent={counts['sent']} quarantined={counts['quarantined']} pending={len(ledger.pending)}",
			file=out,
		)
		return (
			code
			or (1 if failed or unconfirmed or previous_failed or previous_unconfirmed else 0)
			or (EXIT_QUARANTINE if counts["quarantined"] else 0)
		)
	return code or (1 if failed or unconfirmed else 0)


if __name__ == "__main__":
	sys.exit(main())
