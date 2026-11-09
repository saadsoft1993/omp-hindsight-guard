"""Third review: identifier assignments and literal passwords (R9), directory integrity (R12), startup-file markers
(R15), link removal (R16) and doctor's honesty (claims). Each failed before its fix. Secret-looking values are
assembled at run time."""

import io
import os
import stat
import time

import pytest

from omp_hindsight_guard import config as cfg
from omp_hindsight_guard import doctor, shellhooks
from omp_hindsight_guard.redact import RejectBody, redact_json, redact_text
from tests.helpers import make_setup

NAME = "pass" + "word"
SECRET = "Abc123" + "xyz9Q"


# --- R9 -------------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
	"identifier",
	[
		f"{NAME}:{SECRET}",  # no space after the colon: the line-anchored YAML rule never saw it
		f"note {NAME}: {SECRET}",  # ordinary words before the name
		f"mnemopi:{NAME}:{SECRET}",
		f"x/{NAME}:{SECRET}",
		f"tok{'en'}:{SECRET}",
		f"api_{'key'}:{SECRET}",
		f"{NAME} {SECRET}",
	],
)
def test_r9_an_identifier_carrying_an_assignment_is_refused_wherever_it_appears(identifier):
	for body in (
		{"tags": [identifier]},
		{"items": [{"content": "x", "document_id": identifier}]},
		{"items": [{"content": "x", "tags": [identifier]}]},
		{"id": identifier},
	):
		with pytest.raises(RejectBody, match=r"identifier carries a secret|invalid document id"):
			redact_json(body)


def test_r9_ordinary_identifiers_are_still_accepted():
	for good in (
		"mnemopi:alpha:webapp-3tntylzrz3coh:w:a2",
		"project:acme",
		f"type:{NAME}-reset",  # a word that merely mentions the topic
		"source:omp",
		"model:api-key-1",
		"mm-1:x@y.z",
		"session:token",
	):
		assert redact_json({"tags": [good]})[0] == {"tags": [good]}


@pytest.mark.parametrize("value", ["my_secret_pw_123", "CORRECT_HORSE_7", "settings.pw_v2.x1"])
def test_r9_a_code_shaped_password_with_a_digit_is_still_a_password_in_a_literal_context(value):
	assert value not in str(redact_json({NAME: value})[0])
	assert value not in redact_text(f'{NAME} = "{value}"')[0]
	assert value not in redact_text(f'{{"{NAME}": "{value}"}}')[0]


@pytest.mark.parametrize(
	"value", ["get_auth_token", "settings.SERVICE_KEY", "os.environ", "MY_VARIABLE_NAME"]
)
def test_r9_code_references_without_a_digit_are_left_alone(value):
	assert redact_text(f"{NAME} = {value}")[0] == f"{NAME} = {value}"


# --- R12 -------------------------------------------------------------------------------------------------------------


def test_r12_creating_directories_checks_the_directory_they_are_created_in(tmp_path):
	open_parent = tmp_path / "open"
	open_parent.mkdir()
	open_parent.chmod(0o777)
	with pytest.raises(cfg.ConfigError, match="writable by group or other"):
		cfg.makedirs_private(open_parent / "state" / "deeper")
	assert not (open_parent / "state").exists()
	sticky = tmp_path / "sticky"
	sticky.mkdir()
	sticky.chmod(0o1777)
	cfg.makedirs_private(sticky / "mine")  # a sticky shared directory (like /tmp) is fine
	assert stat.S_IMODE((sticky / "mine").stat().st_mode) == 0o700


def test_r12_a_directory_another_process_creates_in_the_meantime_is_not_trusted(tmp_path, monkeypatch):
	real_mkdir = type(tmp_path).mkdir

	def racing(self, mode=0o777, parents=False, exist_ok=False):
		if self.name == "raced":
			real_mkdir(self, mode=0o777)
			self.chmod(0o777)  # what an attacker would have made
			raise FileExistsError(str(self))
		return real_mkdir(self, mode=mode, parents=parents, exist_ok=exist_ok)

	monkeypatch.setattr(type(tmp_path), "mkdir", racing)
	with pytest.raises(cfg.ConfigError, match="writable by group or other"):
		cfg.makedirs_private(tmp_path / "raced")


# --- R15 -------------------------------------------------------------------------------------------------------------

BEGIN, END = shellhooks.BEGIN, shellhooks.END


def rc_file(tmp_path, text):
	rc = tmp_path / "rc"
	rc.write_text(text)
	return rc


def test_r15_missing_end_then_reinstall_then_uninstall_never_deletes_the_users_lines(tmp_path):
	"""Before: add_block appended a second block to an unfinished one; remove_block then deleted everything between."""
	original = f"export A=1\n{BEGIN}\nsource /old/hook\nexport KEEP=precious\nalias gs='git status'\n"
	rc = rc_file(tmp_path, original)
	with pytest.raises(ValueError, match="no end marker"):
		shellhooks.add_block(rc, "source /new/hook")
	assert rc.read_text() == original  # nothing was appended
	with pytest.raises(ValueError, match="no end marker"):
		shellhooks.remove_block(rc)
	assert rc.read_text() == original


@pytest.mark.parametrize(
	("text", "message"),
	[
		(f"a\n{END}\nb\n", "no begin marker"),
		(f"{BEGIN}\nx\n{BEGIN}\ny\n{END}\n", "inside the block"),
		(f"{BEGIN}\nx\n{END}\n{END}\n", "no begin marker"),
	],
)
def test_r15_every_ambiguous_marker_layout_is_refused_by_install_and_uninstall(tmp_path, text, message):
	rc = rc_file(tmp_path, text)
	for operation in (lambda: shellhooks.add_block(rc, "x"), lambda: shellhooks.remove_block(rc)):
		with pytest.raises(ValueError, match=message):
			operation()
		assert rc.read_text() == text


def test_r15_well_formed_blocks_still_install_once_and_remove_cleanly(tmp_path):
	rc = rc_file(tmp_path, "export A=1\n")
	assert shellhooks.add_block(rc, "source /h") is True
	assert shellhooks.add_block(rc, "source /h") is False
	assert shellhooks.remove_block(rc) is True
	assert rc.read_text() == "export A=1\n"


def test_r15_the_install_command_reports_the_problem_and_changes_nothing(tmp_path):
	rc = rc_file(tmp_path, f"{BEGIN}\nunfinished\n")
	out = io.StringIO()
	code = shellhooks.hook_command("zsh", tmp_path / "cfg", install=True, rc=rc, yes=True, out=out)
	assert code == 2 and rc.read_text() == f"{BEGIN}\nunfinished\n"


# --- R16 -------------------------------------------------------------------------------------------------------------


def test_r16_removing_a_link_never_reaches_through_a_symlinked_dot_omp(tmp_path):
	overlays = tmp_path / "overlays"
	overlays.mkdir()
	overlay = overlays / "alpha.yml"
	overlay.write_text("memory:\n  backend: hindsight\n")
	elsewhere = tmp_path / "elsewhere"
	elsewhere.mkdir()
	external = elsewhere / "config.yml"
	external.symlink_to(overlay)  # a link into the overlay directory, living outside the repository
	repo = tmp_path / "repo"
	repo.mkdir()
	(repo / ".omp").symlink_to(elsewhere)
	err = io.StringIO()
	import contextlib

	with contextlib.redirect_stderr(err):
		code = shellhooks.unlink_repo(overlays, repo, out=io.StringIO())
	assert code == 2 and "is a symlink" in err.getvalue()
	assert external.is_symlink() and external.resolve() == overlay.resolve()


def test_r16_a_normal_link_is_still_removed(tmp_path):
	overlays = tmp_path / "overlays"
	overlays.mkdir()
	overlay = overlays / "alpha.yml"
	overlay.write_text("x")
	repo = tmp_path / "repo"
	(repo / ".omp").mkdir(parents=True)
	(repo / ".omp" / "config.yml").symlink_to(overlay)
	assert shellhooks.unlink_repo(overlays, repo, out=io.StringIO()) == 0
	assert not (repo / ".omp").exists()


# --- claims: doctor says what it did -----------------------------------------------------------------------------------


def test_doctor_does_not_claim_an_upstream_key_check_it_skipped(tmp_path, monkeypatch):
	config = make_setup(tmp_path / "cfg", {"alpha": ["~/a"]})
	keys = cfg.load_keys(config)

	def answer(url, key=None):
		if "/health/ready" in url:
			return 200
		if key is None or key == keys.upstream:
			return 401
		return 404 if "other" in url or "/docs" in url or "/banks/alpha/" not in url else 200

	monkeypatch.setattr(doctor, "http_status", answer)
	remote = doctor.check_live(config, keys, "https://memory.example.org")
	isolation = next(r for r in remote if r.name == "isolation alpha")
	assert isolation.level == "ok" and "upstream key 401" not in isolation.detail
	assert "NOT probed" in isolation.detail
	local = doctor.check_live(config, keys, "http://127.0.0.1:1")
	assert "upstream key 401" in next(r for r in local if r.name == "isolation alpha").detail


def make_backups(tmp_path, dump_age_days, export_names=()):
	directory = tmp_path / "backups"
	directory.mkdir()
	dump = directory / "hindsight-2026-01-01-000000.dump"
	dump.write_text("x")
	for path in [dump, *(directory / n for n in export_names)]:
		if path != dump:
			path.write_text("x")
		stamp = time.time() - dump_age_days * 86400
		os.utime(path, (stamp, stamp))
	newest = directory / "hindsight-2026-11-09-000000.dump"
	newest.write_text("x")  # fresh dump, so the 26 h check passes
	return directory


def test_a_bank_with_no_export_is_a_warning_at_first_and_a_failure_once_a_week_has_passed(tmp_path):
	config = make_setup(tmp_path / "cfg", {"alpha": ["~/a"]})
	young = doctor.check_backup(make_backups(tmp_path, 2), 26, config)
	assert [r.level for r in young if r.name == "export alpha"] == ["warn"]
	other = tmp_path / "other"
	other.mkdir()
	old = doctor.check_backup(make_backups(other, 20), 26, config)
	failing = [r for r in old if r.name == "export alpha"]
	assert [r.level for r in failing] == ["fail"] and "no export although backups began" in failing[0].detail


def test_exports_are_recognised_by_the_exact_six_digit_stamp_the_script_writes(tmp_path):
	config = make_setup(tmp_path / "cfg", {"alpha": ["~/a"]})
	good = make_backups(tmp_path, 1, ["export-alpha-2026-11-09-123456.zip"])
	assert [r.level for r in doctor.check_backup(good, 26, config) if r.name == "export alpha"] == ["ok"]
	odd = tmp_path / "odd"
	odd.mkdir()
	bad = make_backups(odd, 1, ["export-alpha-2026-11-09-1234.zip", "export-alpha-2026-11-09-123456-x.zip"])
	assert [r.level for r in doctor.check_backup(bad, 26, config) if r.name == "export alpha"] == ["warn"]
