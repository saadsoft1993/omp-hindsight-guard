# ruff: noqa: F811
"""Third verification pass: lexical ancestry (H1), one folding rule for every consumer (M1), injective and readable
document ids (M2, M4), a routing row with an extra column (M3). Each failed before its fix."""

import re

import pytest

from omp_hindsight_guard import config as cfg
from omp_hindsight_guard import importer as im
from omp_hindsight_guard import routing
from omp_hindsight_guard.redact import RejectBody, redact_json
from tests.test_hook import BANKS_JSON  # noqa: F401
from tests.test_importer import row
from tests.test_review3_hooks import (  # noqa: F401
	BLOCK,
	cache_name,
	launch,
	overlay_args,
	run,
	runner,
	with_url,
	world,
)

DOWN = "http://127.0.0.1:9"


# --- H1: the walk is lexical, so the directory that controls a symlink is checked --------------------------------


def shared_link_to(tmp_path, target):
	"""A world-writable (non-sticky) directory holding a symlink into a private one."""
	shared = tmp_path / "shared"
	shared.mkdir()
	shared.chmod(0o777)
	(shared / "link").symlink_to(target)
	return shared / "link"


def test_h1_a_path_through_a_replaceable_symlink_is_refused_even_though_its_target_is_private(tmp_path):
	private = tmp_path / "private"
	private.mkdir(mode=0o700)
	(private / "overlays").mkdir(mode=0o700)
	link = shared_link_to(tmp_path, private)
	with pytest.raises(cfg.ConfigError, match="writable by group or other"):
		cfg.check_dir_trusted(link / "overlays", "overlay directory")
	with pytest.raises(cfg.ConfigError, match="writable by group or other"):
		cfg.makedirs_private(link / "overlays" / "deeper")
	# the same target reached through a directory only you can write is fine
	mine = tmp_path / "mine"
	mine.mkdir(mode=0o700)
	(mine / "link").symlink_to(private)
	cfg.check_dir_trusted(mine / "link" / "overlays", "overlay directory")


def test_h1_the_importer_refuses_an_overlay_read_through_a_replaceable_symlink(tmp_path):
	from omp_hindsight_guard import overlays

	private = tmp_path / "private"
	private.mkdir(mode=0o700)
	path = private / "alpha.yml"
	path.write_text(
		'memory:\n  backend: hindsight\nhindsight:\n  apiUrl: "http://127.0.0.1:1"\n  apiToken: "k"\n  bankId: "alpha"\n'
	)
	path.chmod(0o600)
	with pytest.raises(cfg.ConfigError, match="writable by group or other"):
		overlays.read_overlay(shared_link_to(tmp_path, private) / "alpha.yml")


def test_h1_launchers_refuse_configuration_reached_through_a_replaceable_symlink(runner, world, tmp_path):
	with_url(world, DOWN)
	link = shared_link_to(tmp_path, tmp_path)  # tmp_path (0700) holds world["overlays"]
	extra = {"OMP_HINDSIGHT_GUARD_OVERLAY_DIR": str(link / "overlays")}
	proc, _ = launch(runner, world, world["home"] / "work/beta-site", extra=extra)
	assert "not in a trusted location" in proc.stderr
	assert proc.stdout.splitlines()[0] == "argv:"  # unchanged: nothing from the untrusted table was applied
	proc, _ = launch(runner, world, world["home"] / "work/beta-site", extra={**extra, **BLOCK}, check=False)
	assert proc.returncode == 75 and proc.stdout == "" and "not in a trusted location" in proc.stderr
	(tmp_path / "shared").chmod(0o700)  # the same arrangement through a directory only you can write
	proc, _ = launch(runner, world, world["home"] / "work/beta-site", extra=extra)
	assert "not in a trusted location" not in proc.stderr


def test_h1_launchers_do_not_cache_into_a_state_directory_behind_a_replaceable_symlink(
	runner, world, tmp_path
):
	with_url(world, DOWN)
	link = shared_link_to(tmp_path, tmp_path)
	state = tmp_path / "state"
	state.mkdir(mode=0o700)
	launch(
		runner,
		world,
		world["home"] / "work/beta-site",
		extra={"OMP_HINDSIGHT_GUARD_STATE_DIR": str(link / "state")},
	)
	assert list(state.iterdir()) == []


# --- M1: one folding rule (A-Z only) in Python and in every launcher -------------------------------------------------


def test_m1_unicode_siblings_route_the_same_way_in_python_and_every_launcher(runner, world, tmp_path):
	home = world["home"]
	for name in ("work/strasse", "work/stra\u00dfe", "work/STRASSE-x", "work/\u00c9cole", "work/\u00e9cole"):
		(home / name / "sub").mkdir(parents=True, exist_ok=True)
	banks = [("alpha", "~/work/strasse")]
	world["routes"].write_text("".join(f"{b}\t{r}\n" for b, r in banks))
	for relative in (
		"work/strasse/sub",
		"work/stra\u00dfe/sub",
		"work/STRASSE-x/sub",
		"work/\u00c9cole/sub",
		"work/other",
	):
		cwd = home / relative
		if not cwd.exists() or (
			relative.startswith("work/stra\u00df") and (home / "work/strasse").samefile(cwd.parent)
		):
			continue  # a filesystem that itself folds the sharp s (default macOS) has no such sibling
		found = routing.route(cwd, banks, home)
		expected = overlay_args(world, found.bank) if found.bank else "argv:"
		assert run(runner, world, cwd)[0] == expected, relative
	# the sibling python used to casefold into the root: no longer (on a filesystem that itself folds the sharp s,
	# such as the default macOS one, there is no sibling at all)
	if (home / "work/stra\u00dfe").resolve().name != "strasse":
		assert routing.route(home / "work/stra\u00dfe/sub", banks, home).bank is None
	assert cfg.canonical("/Work/Caf\u00c9") == "/work/caf\u00c9/"  # A-Z folded, nothing else


# --- M3: exactly two fields ----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
	"line",
	[
		"alpha\t~/work/alpha-app\tunexpected",
		"alpha\t~/work/al\x01pha-app",
		"alpha\t~/work/a\rb",
	],
)
def test_m3_an_extra_column_or_a_control_character_makes_the_table_malformed(runner, world, line):
	world["routes"].write_text(f"beta\t~/work/beta-site\n{line}\n")
	proc, _ = launch(runner, world, world["home"] / "work/alpha-app/ui", extra=BLOCK, check=False)
	assert proc.returncode == 75 and proc.stdout == "" and "malformed entry" in proc.stderr, repr(line)


# --- M2, M4: injective ids the proxy can read back and the redactor will not rewrite ---------------------------------


def identity_row(label, row_id, table="working_memory"):
	return row(label, table, row_id, "alpha", "project:a", "text")


def test_m2_two_different_sources_never_share_a_document_id():
	ids = {
		im.default_document_id(identity_row("work", rid))
		for rid in (
			"a b",
			"a_b",
			"a/b",
			"a#b",
			"x" * 130 + "1",
			"x" * 130 + "2",
			"p..q",
			"p.q",
			"p\u00e9",
			"p_",
		)
	}
	assert len(ids) == 10


def test_m2_a_name_that_already_looks_hashed_is_hashed_again_not_taken_as_is():
	crafted = identity_row("work", "ab@h" + "0" * 64)
	assert im.default_document_id(crafted).count("@h") == 2  # the hash of the whole identity is appended
	assert im.default_document_id(crafted) != im.default_document_id(identity_row("work", "ab"))


def test_m2_ids_that_were_already_fine_are_unchanged():
	assert im.default_document_id(identity_row("pilot-k2j3", "p1")) == "mnemopi:alpha:pilot-k2j3:w:p1"


def test_m2_a_later_run_cannot_overwrite_another_sources_document():
	"""S1 (id `a b`) was sent; later S2 (id `a_b`, other content) must not get S1's document id."""
	s1 = row("work", "working_memory", "a b", "alpha", "project:a", "first")
	s2 = row("work", "working_memory", "a_b", "alpha", "project:a", "second")
	ledger = im.Ledger()
	docs = im.dedupe([s1])
	im.apply_ledger(docs, ledger)
	im.record(ledger, docs)
	later = im.dedupe([s2])
	assert im.apply_ledger(later, ledger) == []
	assert im.doc_id_of(later[0]) not in ledger.documents


@pytest.mark.parametrize("rid", ["a b", "a/b", "w..old", "caf\u00e9", "x" * 300, "p#q?r", "a@h" + "0" * 64])
def test_m4_every_generated_id_passes_the_write_validation_unchanged_and_reads_back_through_the_proxy_rules(
	rid,
):
	doc_id = im.default_document_id(identity_row("my label/x..y", rid))
	assert re.fullmatch(r"[A-Za-z0-9:_.\-@]{1,200}", doc_id) and ".." not in doc_id
	body = redact_json({"items": [{"content": "x", "document_id": doc_id}]})[0]
	assert body["items"][0]["document_id"] == doc_id  # stored under exactly the id that was recorded


@pytest.mark.parametrize(
	"bad",
	["mnemopi:alpha:work..old:w:1", "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", "a" * 201, ""],
)
def test_m4_ids_that_could_not_be_stored_as_given_are_refused_not_rewritten(bad):
	with pytest.raises(RejectBody, match=r"invalid document id|invalid identifier"):
		redact_json({"items": [{"content": "x", "document_id": bad}]})
