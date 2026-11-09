# ruff: noqa: F811
"""Regression tests for the second independent review. Each failed before its fix (finding numbers in the names).
Anything secret-looking is assembled at run time."""

import json
import os
import urllib.error

import pytest
import yaml

from omp_hindsight_guard import config as cfg
from omp_hindsight_guard import doctor, overlays, routing
from omp_hindsight_guard import importer as im
from omp_hindsight_guard.redact import RejectBody, redact_json, redact_text
from tests.helpers import make_setup
from tests.test_importer import (  # noqa: F401
	FakeOpener,
	dry_digest,
	row,
	run_main,
	world,
	write_banks_json,
	write_overlays,
)

# --- 2: configuration integrity is enforced by the loader ---------------------------------------------------------


def minimal(tmp_path):
	data = {"version": 1, "proxy": {"upstream_key_file": "u.key"}, "banks": {"w": {"key_file": "w.key"}}}
	path = tmp_path / "cfg" / "banks.json"
	path.parent.mkdir(mode=0o700)
	path.write_text(json.dumps(data))
	path.chmod(0o600)
	return path


def test_f2_a_group_or_world_writable_config_file_is_refused(tmp_path):
	path = minimal(tmp_path)
	assert cfg.load_config(path).banks[0].name == "w"
	for mode in (0o620, 0o602, 0o666):
		path.chmod(mode)
		with pytest.raises(cfg.ConfigError, match="writable by group or other"):
			cfg.load_config(path)


def test_f2_a_config_in_a_directory_others_can_write_is_refused(tmp_path):
	path = minimal(tmp_path)
	path.parent.chmod(0o770)
	with pytest.raises(cfg.ConfigError, match="directory"):
		cfg.load_config(path)
	path.parent.chmod(0o700)
	assert cfg.load_config(path)


def test_f2_a_key_file_in_a_writable_directory_is_refused(tmp_path):
	d = tmp_path / "keys"
	d.mkdir(mode=0o700)
	key = d / "k.key"
	key.write_text("k" * 40)
	key.chmod(0o600)
	assert cfg.read_key(key, "t") == "k" * 40
	d.chmod(0o777)
	with pytest.raises(cfg.ConfigError, match="directory"):
		cfg.read_key(key, "t")


def test_f2_existing_unsafe_directories_are_rejected_not_reused(tmp_path):
	loose = tmp_path / "loose"
	loose.mkdir()
	loose.chmod(0o777)
	with pytest.raises(cfg.ConfigError, match="writable by group or other"):
		cfg.makedirs_private(loose)
	ok = tmp_path / "ok"
	ok.mkdir()
	ok.chmod(0o755)
	cfg.makedirs_private(ok / "child")  # a directory nobody else can write into is fine


# --- 3: content already in one bank, going to a second bank ---------------------------------------------------------


def test_f3_content_in_a_second_bank_from_its_own_source_row_is_reported_not_blocked():
	"""{A} -> {A, B} with a distinct source row in B is that row's own memory (routed by its own folder). It is
	allowed, listed, and a source row that MOVES banks is still refused."""
	a = row("a-1", "working_memory", "1", "alpha", "project:a", "same text")
	b = row("b-1", "working_memory", "2", "beta", "project:b", "same text")
	docs = im.dedupe([a, b])
	ledger = im.Ledger()
	im.apply_ledger(im.dedupe([a]), ledger)
	im.record(ledger, im.dedupe([a]))
	conflicts = im.apply_ledger(docs, ledger)
	assert conflicts == []
	# listed for both documents: against the ledger (alpha's copy) and against this same run (the other copy)
	assert sorted((r.key, banks) for r, banks in im.content_copies(docs, ledger)) == sorted(
		[(a.key, ["beta"]), (b.key, ["alpha"])]
	)
	moved = row(
		"a-1", "working_memory", "1", "beta", "project:a", "same text"
	)  # the same source row, new bank
	assert [why for _, _, why in im.apply_ledger(im.dedupe([moved]), ledger)] == ["source"]


def test_f3_the_report_lists_content_that_is_also_in_another_bank(world):
	write_overlays(world["overlays"])
	run_main(world, "--send", "--confirm", dry_digest(world), opener=FakeOpener())
	import sqlite3

	conn = sqlite3.connect(world["root"] / "other-zzz" / "mnemopi.db")
	conn.execute(
		"UPDATE working_memory SET content = 'case lesson', metadata_json = ? WHERE id = 'o1'",
		(json.dumps({"cwd": str(world["en"])}),),
	)
	conn.commit()
	conn.close()
	_, text = run_main(world)
	assert "content-also-in:\tother-zzz\tworking_memory\to1\t-> alpha\talso-in=beta" in text


# --- 4: serialised imports, reservations before sending -----------------------------------------------------------


def test_f4_a_second_import_cannot_run_while_one_holds_the_ledger_lock(world):
	write_overlays(world["overlays"])
	digest = dry_digest(world)
	opener = FakeOpener()
	with im.ledger_lock(world["state"] / im.LEDGER_NAME):
		code, text = run_main(world, "--send", "--confirm", digest, opener=opener)
	assert code == im.EXIT_BUSY and opener.requests == [] and "another import" in text
	code, _ = run_main(world, "--send", "--confirm", digest, opener=FakeOpener())
	assert code == 0  # the lock was released


def test_f4_an_unconfirmed_send_stays_reserved_and_blocks_a_different_destination(world):
	write_overlays(world["overlays"])
	boom = FakeOpener([urllib.error.URLError("timed out")])
	code, _ = run_main(world, "--send", "--confirm", dry_digest(world), opener=boom)
	assert code == 1
	ledger = json.loads((world["state"] / im.LEDGER_NAME).read_text())
	assert ledger["pending"] and not ledger["sources"]
	# Routing changes between runs (the other import's configuration): the reservation is what remembers where
	# the rows were sent.
	data = json.loads(world["config"].read_text())
	data["banks"]["alpha"]["roots"], data["banks"]["beta"]["roots"] = (
		["~/work/beta-site"],
		["~/work/alpha-app"],
	)
	world["config"].write_text(json.dumps(data))
	_, text = run_main(world)
	assert "ledger-conflict:" in text and "\tsource" in text
	assert "ledger_conflicts=0" not in text


def test_f4_a_refusal_before_anything_was_stored_releases_the_reservation(world):
	write_overlays(world["overlays"])
	code, _ = run_main(world, "--send", "--confirm", dry_digest(world), opener=FakeOpener([422]))
	assert code == 1
	assert json.loads((world["state"] / im.LEDGER_NAME).read_text())["pending"] == {}


# --- 5: accepted is not synchronised -----------------------------------------------------------------------------


def test_f5_rows_stay_unsynced_until_the_operation_completes(world):
	write_overlays(world["overlays"])
	pending = FakeOpener(op_status="pending")
	code, text = run_main(world, "--send", "--confirm", dry_digest(world), opener=pending)
	assert code == 0 and "operations: confirmed=0 failed=0 unconfirmed=0 dropped=0 pending=" in text
	assert run_main(world, "--count-unsynced")[1] == "unsynced=4\n"
	code, text = run_main(world, "--reconcile", opener=FakeOpener(op_status="completed"))
	assert code == 0 and "confirmed=" in text
	assert run_main(world, "--count-unsynced")[1] == "unsynced=0\n"
	assert json.loads((world["state"] / im.LEDGER_NAME).read_text())["pending"] == {}


def test_f5_a_failed_operation_leaves_the_rows_actionable(world):
	write_overlays(world["overlays"])
	run_main(world, "--send", "--confirm", dry_digest(world), opener=FakeOpener(op_status="pending"))
	code, text = run_main(world, "--reconcile", opener=FakeOpener(op_status="failed"))
	assert code == 1 and "failed=" in text
	assert run_main(world, "--count-unsynced")[1] == "unsynced=4\n"
	_, report = run_main(world, "--only-new")
	assert "requests=2 items=4" in report  # everything is offered again
	ledger = json.loads((world["state"] / im.LEDGER_NAME).read_text())
	# ... but only to the banks they went to: a failed operation may still have left the document there
	assert ledger["pending"] == {} and len(ledger["failed"]) == 4


def test_f5_an_unknown_operation_state_stays_pending(world):
	write_overlays(world["overlays"])
	run_main(world, "--send", "--confirm", dry_digest(world), opener=FakeOpener(op_status="queued"))
	code, text = run_main(world, "--reconcile", opener=FakeOpener(op_status="running"))
	assert code == 1 and "-> unknown" in text and "unconfirmed=4" in text  # reported, never silent
	assert run_main(world, "--count-unsynced")[1] == "unsynced=4\n"


def test_f5_a_reply_without_operation_ids_is_never_taken_as_synced(world):
	"""Every request is asynchronous, so a reply with no usable operation id proves nothing (review 3, R3)."""
	from tests.test_importer import FakeResponse

	class NoOps(FakeOpener):
		def open(self, req, timeout=None):
			if req.get_method() == "POST":
				self.requests.append(req)
				return FakeResponse(200, b'{"success": true}')
			return super().open(req, timeout)

	write_overlays(world["overlays"])
	code, text = run_main(world, "--send", "--confirm", dry_digest(world), opener=NoOps())
	assert code == 1 and "no usable operation id" in text and "unconfirmed=4" in text
	assert run_main(world, "--count-unsynced")[1] == "unsynced=4\n"
	assert len(json.loads((world["state"] / im.LEDGER_NAME).read_text())["pending"]) == 4


# --- 6: stale content -> document mappings -------------------------------------------------------------------------


def test_f6_restoring_old_content_is_not_considered_synced_after_it_was_overwritten():
	def send(ledger, content):
		r = row("a-1", "working_memory", "1", "alpha", "project:a", content)
		docs = im.dedupe([r])
		assert im.apply_ledger(docs, ledger) == []
		im.record(ledger, docs)
		return r

	ledger = im.Ledger()
	x = send(ledger, "X")
	assert im.synced(x, ledger)
	y = send(ledger, "Y")
	assert im.synced(y, ledger)
	restored = row("a-1", "working_memory", "1", "alpha", "project:a", "X")
	assert not im.synced(restored, ledger)
	assert im.content_hash("X") not in ledger.contents  # the obsolete reverse mapping is gone
	assert ledger.documents[im.default_document_id(restored)]["sha"] == im.content_hash("Y")


def test_f6_a_reverse_mapping_that_disagrees_with_its_document_is_ignored():
	r = row("a-1", "working_memory", "1", "alpha", "project:a", "X")
	ledger = im.Ledger(
		documents={"d": {"bank": "alpha", "sha": "other"}},
		contents={im.content_hash("X"): {"alpha": "d"}},
		sources={r.source_key: "alpha"},
	)
	assert not im.synced(r, ledger)


# --- 7: roots are canonicalised the way routing does it --------------------------------------------------------------


def parse(tmp_path, **banks):
	data = {"version": 1, "proxy": {"upstream_key_file": "u.key"}, "banks": banks}
	return cfg.parse_config(data, tmp_path / "banks.json")


def test_f7_a_root_that_resolves_to_slash_or_home_is_too_broad(tmp_path, scratch_home):
	for root in ("/usr/..", "/usr/bin/../..", str(scratch_home / "x" / ".."), "~/x/..", "~/."):
		with pytest.raises(cfg.ConfigError, match="must not contain"):  # no launcher could reproduce these
			parse(tmp_path, a={"key_file": "k", "roots": [root]})
	(tmp_path / "homelink").symlink_to(scratch_home)
	with pytest.raises(
		cfg.ConfigError, match="too broad"
	):  # a plain spelling that resolves to the home directory
		parse(tmp_path, a={"key_file": "k", "roots": [str(tmp_path / "homelink")]})


def test_f7_two_spellings_of_one_directory_cannot_belong_to_two_banks(tmp_path, scratch_home):
	(scratch_home / "project").mkdir()
	with pytest.raises(cfg.ConfigError, match="already a root of bank a"):
		parse(
			tmp_path,
			a={"key_file": "k", "roots": ["~/project"]},
			b={"key_file": "k2", "roots": [str(scratch_home / "project")]},
		)
	with pytest.raises(cfg.ConfigError, match="must not contain"):
		parse(
			tmp_path,
			a={"key_file": "k", "roots": ["~/project"]},
			b={"key_file": "k2", "roots": ["~/other/../project/"]},
		)


def test_f7_symlink_aliases_of_one_directory_cannot_belong_to_two_banks(tmp_path):
	real = tmp_path / "real"
	real.mkdir()
	(tmp_path / "one").symlink_to(real)
	(tmp_path / "two").symlink_to(real)
	with pytest.raises(cfg.ConfigError, match="already a root of bank a"):
		parse(
			tmp_path,
			a={"key_file": "k", "roots": [str(tmp_path / "one")]},
			b={"key_file": "k2", "roots": [str(tmp_path / "two")]},
		)
	same = parse(tmp_path, a={"key_file": "k", "roots": [str(tmp_path / "one"), str(tmp_path / "two")]})
	assert len(same.banks[0].roots) == 2  # the same bank may list aliases


def test_f7_routing_never_picks_between_equally_long_matches_by_file_order(tmp_path):
	real = tmp_path / "real"
	(real / "sub").mkdir(parents=True)
	(tmp_path / "one").symlink_to(real)
	banks = [("a", str(real)), ("b", str(tmp_path / "one"))]  # a config written before the alias existed
	result = routing.route(real / "sub", banks, tmp_path)
	assert result.bank is None and result.ambiguous
	assert routing.route(real / "sub", [("a", str(real)), ("a", str(tmp_path / "one"))], tmp_path).bank == "a"


# --- 8 and 9: redaction ---------------------------------------------------------------------------------------------

V_PUNCT = "Abc(123)" + "xyz9"
V_QUOTED = "Tr0ub(4)" + "dor&3"


def test_f8_passwords_with_brackets_are_redacted_when_the_context_says_literal():
	out, counts = redact_json(
		{"items": [{"content": "x", "metadata": {"password": V_PUNCT, "api_keys": [V_PUNCT]}}]}
	)
	meta = out["items"][0]["metadata"]
	assert meta == {"password": "[REDACTED:assignment]", "api_keys": ["[REDACTED:assignment]"]}
	assert counts["assignment"] == 2
	for text in (f'password = "{V_QUOTED}"', f"{{'secret': '{V_QUOTED}'}}", f'PASSWORD="{V_QUOTED}"'):
		out, _ = redact_text(text)
		assert V_QUOTED not in out, out


@pytest.mark.parametrize(
	"text",
	[
		"token = get_token()",
		"password_field = forms.CharField(max_length=128)",
		'token = "${TOKEN}"',
		'password = "<password>"',
		'api_key = "{api_key}"',
		"auth = request.headers['x']",
		'secret = os.environ["X"]',
		"token: str = field(default_factory=make)",
		"api_key = settings.API_KEY",
	],
)
def test_f8_code_expressions_are_still_left_alone(text):
	assert redact_text(text)[0] == text


def test_f9_an_identifier_that_carries_a_secret_assignment_is_refused():
	pairs = [
		("pass" + "word", "Abc123xyz9Q"),
		("sec" + "ret", "Qq9Ww8Ee7Rr6"),
		("api_" + "key", "Zq81mmPa0x77"),
		("tok" + "en", "abcDEF123456"),
	]
	for body in (
		{"tags": [f"{pairs[0][0]}: {pairs[0][1]}"]},
		{"items": [{"content": "x", "tags": [f"{pairs[1][0]}: {pairs[1][1]}"]}]},
		{"items": [{"content": "x", "document_id": f"{pairs[2][0]}: {pairs[2][1]}"}]},
		{"id": f"{pairs[3][0]}: {pairs[3][1]}"},
	):
		with pytest.raises(RejectBody):
			redact_json(body)
	ok = {"tags": ["project:acme", "source:omp", "model:api-key-1"], "id": "mm-1:x@y.z"}
	assert redact_json(ok)[0] == ok


# --- 10, 11, 12: overlays ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["null", "true", "123", "no", "1e3", "off", "0x10"])
def test_f10_bank_names_that_yaml_would_retype_round_trip_as_strings(tmp_path, name):
	config = make_setup(tmp_path / "cfg", {name: ["~/a"]})
	overlays.write_overlays(config, tmp_path / "o")
	path = tmp_path / "o" / f"{name}.yml"
	assert yaml.safe_load(path.read_text())["hindsight"]["bankId"] == name
	assert overlays.overlay_bank(path) == name
	assert overlays.read_overlay(path).bank == name


@pytest.mark.parametrize(
	"url",
	[
		"https://user:pw@h.example",
		"https://user@h.example",
		"https://h.example?x=1",
		"https://h.example/p?x=1",
		"https://h.example/p#frag",
		"https://h.example#frag",
		"https://h.example:99999",
		"https://h.example:abc",
		"https://h.example:0",
		"https://h.example/p;params",
		"https://",
		"https://h.example\\x",
	],
)
def test_f11_urls_with_credentials_queries_fragments_or_bad_ports_are_refused(url):
	with pytest.raises(ValueError, match="apiUrl"):
		overlays.check_api_url(url)


def test_f11_a_base_path_is_supported_and_joined_structurally():
	overlays.check_api_url("https://h.example:8898/memory/v2")
	overlays.check_api_url("http://127.0.0.1:8888/")
	overlays.check_api_url("http://[::1]:8888")


def test_f11_doctor_does_not_print_a_credential_bearing_url(tmp_path, scratch_home, monkeypatch):
	import io

	cfg_dir = tmp_path / "cfg"
	config = make_setup(cfg_dir, {"alpha": ["~/a"]})
	overlays.write_overlays(config, cfg_dir / "overlays")
	secret_url = "https://user:" + "hunter2Pw" + "@" + "proxy.example.com"
	buf = io.StringIO()
	doctor.run_doctor(config.path, env={cfg.ENV_CONFIG_DIR: str(cfg_dir)}, out=buf, proxy_url=secret_url)
	assert "hunter2Pw" not in buf.getvalue()


def test_f12_the_importer_uses_one_read_for_url_token_and_bank(world, monkeypatch):
	write_overlays(world["overlays"])
	calls = []
	real = overlays.read_overlay

	def spy(path):
		calls.append(path)
		return real(path)

	monkeypatch.setattr(im, "read_overlay", spy)
	monkeypatch.setattr(overlays, "overlay_bank", lambda p: pytest.fail("reopened the overlay by name"))
	code, _ = run_main(world, "--send", "--confirm", dry_digest(world), opener=FakeOpener())
	assert code == 0 and {p.name for p in calls} == {"alpha.yml", "beta.yml"}


def test_f12_an_overlay_that_is_not_a_regular_file_is_refused(tmp_path):
	d = tmp_path / "x.yml"
	d.mkdir()
	with pytest.raises((ValueError, OSError)):
		overlays.read_overlay(d)
	fifo = tmp_path / "f.yml"
	os.mkfifo(fifo, 0o600)
	with pytest.raises((ValueError, OSError)):
		overlays.read_overlay(fifo)


# --- 14: output directories --------------------------------------------------------------------------------------------


def test_f14_overlay_generation_never_replaces_a_file_it_did_not_write(tmp_path):
	config = make_setup(tmp_path / "cfg", {"alpha": ["~/a"]})
	out = tmp_path / "o"
	out.mkdir(mode=0o700)
	mine = out / "alpha.yml"
	mine.write_text("# my own settings\nmemory:\n  backend: off\n")
	with pytest.raises(ValueError, match="not an overlay directory"):
		overlays.write_overlays(config, out)
	assert mine.read_text().startswith("# my own settings")
	mine.unlink()
	(out / ".hidden-note").write_text("x")
	with pytest.raises(ValueError, match="not an overlay directory"):
		overlays.write_overlays(config, out)
	(out / ".hidden-note").unlink()
	overlays.write_overlays(config, out)
	overlays.write_overlays(config, out)  # replacing its own files is fine


def test_f14_a_symlinked_overlay_directory_is_refused(tmp_path):
	config = make_setup(tmp_path / "cfg", {"alpha": ["~/a"]})
	target = tmp_path / "elsewhere"
	target.mkdir(mode=0o755)
	target.chmod(0o755)
	link = tmp_path / "o"
	link.symlink_to(target)
	with pytest.raises(ValueError, match="symlink"):
		overlays.write_overlays(config, link)
	assert os.stat(target).st_mode & 0o777 == 0o755 and list(target.iterdir()) == []


# --- 16: script dispatch -------------------------------------------------------------------------------------------------


def test_f16_an_invalid_or_wrong_explicit_config_stops_the_script_command(tmp_path, monkeypatch, capsys):
	from omp_hindsight_guard import cli

	bad = tmp_path / "bad.json"
	bad.write_text("{nope")
	bad.chmod(0o600)
	ran = []
	monkeypatch.setattr(
		cli.subprocess, "run", lambda *a, **k: ran.append(a) or type("R", (), {"returncode": 0})()
	)
	assert cli.main(["--config", str(bad), "backup"]) == 2
	assert cli.main(["--config", str(tmp_path / "missing.json"), "backup"]) == 2
	err = capsys.readouterr().err
	assert ran == [] and "not valid JSON" in err and "no configuration at" in err
	# No explicit config and no default file: run with the environment alone.
	assert cli.main(["backup"]) == 0 and len(ran) == 1
	# A default config file that exists but is broken is an error too.
	monkeypatch.setenv(cfg.ENV_CONFIG_DIR, str(tmp_path / "d"))
	(tmp_path / "d").mkdir(mode=0o700)
	(tmp_path / "d" / "banks.json").write_text("{nope")
	(tmp_path / "d" / "banks.json").chmod(0o600)
	assert cli.main(["backup"]) == 2 and len(ran) == 1


# keep the helper import used
_ = write_banks_json
