"""Regression tests for the independent review (H1, M2, M3, M5, L1, L4-L7, L10). Each one failed before its fix.
Fixtures that look like secrets are assembled at run time from neutral-named parts."""

import io
import os

import pytest
import yaml

from omp_hindsight_guard import cli, doctor, overlays, routing, shellhooks
from omp_hindsight_guard import importer as im
from omp_hindsight_guard.redact import RejectBody, redact_json, redact_text, residual_findings
from tests.helpers import make_setup

# --- H1: spaced, unquoted assignments (INI, TOML, .npmrc, ~/.aws/credentials) ------------------------------------

V_AWS = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYzEXAMPLEKEY"
V_PW1 = "s3cretValue" + "9"
V_PW2 = "Tr0ub4dor" + "3x"
V_UUID = "0f6e4a2c-1b3d-4c5e-" + "8f7a-9b0c1d2e3f4a"
V_TOK = "abc123xyz" + "Z9"

SPACED = [
	(f"[default]\naws_secret_access_key = {V_AWS}\n", V_AWS),
	(f"[pypi]\nusername = __token__\npassword = {V_PW1}\n", V_PW1),
	(f"[client]\nuser = root\npassword = {V_PW2}\n", V_PW2),
	(f"//registry.example.com/:_authToken={V_UUID}\n", V_UUID),
	(f"always-auth=true\n//npm.example.com/:_authToken={V_UUID}", V_UUID),
	(f"token = {V_TOK}", V_TOK),
	(f"password = {V_PW1}  # the old one\n", V_PW1),
	(f"password = {V_PW1}\r\nnext = 1\r\n", V_PW1),
	(f"[db]\n  password   =   {V_PW1}\t\n", V_PW1),
	(f"client_secret = {V_PW2}\nname = x", V_PW2),
]


@pytest.mark.parametrize(("text", "secret"), SPACED)
def test_spaced_unquoted_assignments_are_redacted(text, secret):
	out, counts = redact_text(text)
	assert secret not in out, out
	assert sum(counts.values()) >= 1
	again, more = redact_text(out)
	assert again == out and not more
	assert residual_findings(out) == []


@pytest.mark.parametrize(("text", "secret"), SPACED[:4])
def test_the_residual_scan_flags_what_redaction_would_have_caught(text, secret):
	assert "secret-assignment" in [kind for kind, _ in residual_findings(text)], text


QUIET = [
	"token = get_token()",
	"password = forms.CharField(max_length=128)",
	"secret = None",
	"key = value",
	"api_key = settings.API_KEY",
	"max_tokens = 4096",
	"token_type = bearer",
	"password = <password>",
	"password = ${DB_PASSWORD}",
	"auth = request.headers",
	"timeout = 30",
	"username = __token__",
	"password_field = forms_password",
	"secret = os.environ['X']",
	"always-auth=true",
	"//registry.example.com/:_authToken=${NPM_TOKEN}",
	"[client]\nuser = root\nport = 3306\n",
	"if token = other:",
]


@pytest.mark.parametrize("text", QUIET)
def test_ordinary_spaced_assignments_are_left_alone(text):
	assert redact_text(text) == (text, {}) or redact_text(text)[0] == text
	assert residual_findings(text) == []


# --- M2: a secret-named key whose value is a list or an object ----------------------------------------------------

V_LIST = "Zq81mmPa0x" + "77"


def test_a_secret_named_key_with_a_list_or_object_value_is_redacted():
	body = {
		"items": [
			{
				"content": "x",
				"metadata": {
					"tokens": [V_LIST, "short"],
					"passwords": {"primary": [V_LIST], "n": 3},
					"api_keys": {"deep": {"deeper": V_LIST}},
					"notes": [V_LIST],
				},
			}
		],
		"credentials": [V_LIST],
	}
	out, counts = redact_json(body)
	meta = out["items"][0]["metadata"]
	assert meta["tokens"] == ["[REDACTED:assignment]", "short"]
	assert meta["passwords"] == {"primary": ["[REDACTED:assignment]"], "n": 3}
	assert meta["api_keys"] == {"deep": {"deeper": "[REDACTED:assignment]"}}
	assert out["credentials"] == ["[REDACTED:assignment]"]
	assert meta["notes"] == [V_LIST]  # an ordinary name gives a bare string no context
	assert counts["assignment"] == 4


# --- M3: URL parameter names --------------------------------------------------------------------------------------

V_SIG = "9f86d081884c7d659a2feaa0c55ad015" + "a3bf4f1b2b0b822cd15d6c15b0f00a08"
V_LONG = "IQoJb3JpZ2luX2VjE" + "Jz3///////////wEaCXVzLWVhc3QtMSJHMEUCIQD"
V_CRED = "AKIA" + "Q3EXAMPLE7KZ2M4P/20260101/us-east-1/s3/aws4_request"
V_REF = "rt-4f9d8c7b6a5e" + "3d2c1b0a"

URL_PARAMS = [
	(f"https://b.s3.example.com/f?X-Amz-Signature={V_SIG}&X-Amz-Expires=60", V_SIG),
	(f"https://b.s3.example.com/f?x-amz-signature={V_SIG}", V_SIG),
	(f"https://b.s3.example.com/f?a=1&X-Amz-Security-Token={V_LONG}", V_LONG),
	(f"https://b.s3.example.com/f?X-Amz-Credential={V_CRED}&X-Amz-Date=1", V_CRED),
	(f"https://auth.example.com/cb?refresh_token={V_REF}&state=ok", V_REF),
	(f"https://auth.example.com/cb?id_token={V_REF}", V_REF),
	(f"https://git.example.com/api?private_token={V_REF}", V_REF),
	(f"https://x.example.com/?auth_token={V_REF}", V_REF),
	(f"https://x.example.com/?ACCESS_TOKEN={V_REF}", V_REF),
	(f"https://x.example.com/?accessToken={V_REF}", V_REF),
	(f"https://x.example.com/?client-secret={V_REF}", V_REF),
]


@pytest.mark.parametrize(("text", "secret"), URL_PARAMS)
def test_url_parameter_names_are_matched_by_meaning(text, secret):
	out, counts = redact_text(text)
	assert secret not in out and sum(counts.values()) >= 1, out


@pytest.mark.parametrize(
	"text",
	[
		"https://x.example.com/list?sort_key=created_at&page=2",
		"https://x.example.com/?monkey=banana123456789",
		"https://docs.python.org/3/library/re.html?highlight=key#module-re",
		"https://x.example.com/?tokenizer=gpt2-model-name-long",
		"https://x.example.com/?keyword=something-long-value-here",
		"https://x.example.com/?X-Amz-Date=20260101T000000Z&X-Amz-Expires=3600",
		"https://x.example.com/?token={token}&page={page}",
	],
)
def test_ordinary_url_parameters_are_left_alone(text):
	assert redact_text(text)[0] == text


# --- L1: token-only positions are format-checked ------------------------------------------------------------------


@pytest.mark.parametrize(
	"body",
	[
		{"items": [{"content": "x", "entities": [{"text": "t", "type": "password=" + V_PW1}]}]},
		{"items": [{"content": "x", "timestamp": "token: " + V_PW1}]},
		{"items": [{"content": "x", "update_mode": "a\nb"}]},
		{"types": ["world", "has space=oops!"]},
		{"budget": "x" * 201},
		{"tags_match": "any;all"},
		{"trigger": {"mode": "mode=" + V_PW1}},
		{"async": "yes please!"},
	],
)
def test_token_only_fields_must_look_like_identifiers(body):
	with pytest.raises(RejectBody):
		redact_json(body)


def test_ordinary_values_of_those_fields_still_pass():
	body = {
		"async": True,
		"budget": "mid",
		"types": ["world", "experience"],
		"tags_match": "any",
		"trigger": {"mode": "on_retain"},
		"items": [
			{
				"content": "x",
				"timestamp": "2026-11-09T10:00:00Z",
				"entities": [{"text": "a", "type": "PERSON"}],
			}
		],
	}
	assert redact_json(body)[0] == body


# --- M5 and L6, L7: hook installer --------------------------------------------------------------------------------


def test_uninstall_without_an_end_marker_leaves_the_file_alone(tmp_path, capsys):
	rc = tmp_path / ".zshrc"
	original = f"export A=1\n{shellhooks.BEGIN}\nsource x\nexport KEEP=1\nalias ll='ls -l'\n"
	rc.write_text(original)
	with pytest.raises(ValueError, match="end marker"):
		shellhooks.remove_block(rc)
	assert rc.read_text() == original
	assert cli.main(["hook", "zsh", "--uninstall", "--rc", str(rc)]) == 2
	assert "end marker" in capsys.readouterr().err
	assert rc.read_text() == original


def test_uninstall_keeps_everything_around_a_complete_block(tmp_path):
	rc = tmp_path / ".zshrc"
	rc.write_text(f"a\n{shellhooks.BEGIN}\nsource x\n{shellhooks.END}\nb\n")
	assert shellhooks.remove_block(rc) is True
	assert rc.read_text() == "a\nb\n"
	assert not [p for p in tmp_path.iterdir() if p.name.startswith(".zshrc.")]  # no temp file left


def test_uninstall_through_a_symlinked_startup_file_keeps_the_link(tmp_path):
	real = tmp_path / "dotfiles" / "zshrc"
	real.parent.mkdir()
	real.write_text(f"a\n{shellhooks.BEGIN}\nsource x\n{shellhooks.END}\n")
	link = tmp_path / ".zshrc"
	link.symlink_to(real)
	assert shellhooks.remove_block(link) is True
	assert link.is_symlink() and real.read_text() == "a\n"


def test_home_relative_paths_are_escaped_too(tmp_path):
	odd = tmp_path / 'we"ird $x `y` \\z' / "hook.zsh"
	line = shellhooks.shell_quote_path(odd, home=tmp_path)
	assert line == '"$HOME/we\\"ird \\$x \\`y\\` \\\\z/hook.zsh"'
	fish = shellhooks.shell_quote_path(odd, home=tmp_path, syntax="fish")
	assert fish == '"$HOME/we\\"ird \\$x `y` \\\\z/hook.zsh"'  # fish does not escape the backtick
	assert shellhooks.startup_line("zsh", odd, "fish", home=tmp_path) == f"source {fish}"
	assert shellhooks.shell_quote_path(tmp_path / "plain" / "x", home=tmp_path) == '"$HOME/plain/x"'


def test_link_refuses_a_repo_whose_dot_omp_is_a_symlink(tmp_path, scratch_home, capsys):
	cfg_dir = tmp_path / "cfg"
	os.environ["OMP_HINDSIGHT_GUARD_CONFIG_DIR"] = str(cfg_dir)
	try:
		make_setup(cfg_dir, {"alpha": ["~/work/alpha"]})
		assert cli.main(["overlays"]) == 0
		repo = scratch_home / "work/alpha/app"
		repo.mkdir(parents=True)
		elsewhere = scratch_home / "global-omp"
		elsewhere.mkdir()
		(repo / ".omp").symlink_to(elsewhere)
		capsys.readouterr()
		assert cli.main(["link", str(repo)]) == 2
		assert ".omp" in capsys.readouterr().err
		assert list(elsewhere.iterdir()) == []
	finally:
		del os.environ["OMP_HINDSIGHT_GUARD_CONFIG_DIR"]


# --- L5: overlay URL cannot inject YAML ---------------------------------------------------------------------------


@pytest.mark.parametrize(
	"url",
	["https://h.example\n  bankId: x", "https://h.example\tx", "https://h .example", "https://h.example\x00"],
)
def test_overlay_urls_with_whitespace_or_control_characters_are_refused(tmp_path, url):
	config = make_setup(tmp_path / "cfg", {"alpha": ["~/a"]})
	with pytest.raises(ValueError, match="apiUrl"):
		overlays.write_overlays(config, tmp_path / "o", url)
	assert not (tmp_path / "o").exists()


def test_the_overlay_url_is_written_quoted_and_round_trips(tmp_path):
	config = make_setup(tmp_path / "cfg", {"alpha": ["~/a"]})
	overlays.write_overlays(config, tmp_path / "o", "https://h.example:8898/base/v1")
	text = (tmp_path / "o/alpha.yml").read_text()
	assert 'apiUrl: "https://h.example:8898/base/v1"' in text
	assert yaml.safe_load(text)["hindsight"]["apiUrl"] == "https://h.example:8898/base/v1"
	assert overlays.load_overlay(tmp_path / "o/alpha.yml")[0] == "https://h.example:8898/base/v1"


# --- L4: doctor --proxy-url ---------------------------------------------------------------------------------------


@pytest.fixture
def live(tmp_path, scratch_home, monkeypatch):
	cfg_dir = tmp_path / "cfg"
	config = make_setup(cfg_dir, {"alpha": ["~/a"], "beta": ["~/b"]})
	overlays.write_overlays(config, cfg_dir / "overlays")
	calls = []

	def fake(url, key=None):
		calls.append((url, key))
		return 200 if url.endswith("/health/ready") else 404

	monkeypatch.setattr(doctor, "http_status", fake)
	return config, {"OMP_HINDSIGHT_GUARD_CONFIG_DIR": str(cfg_dir)}, calls


def run_live(config, env, **kw):
	buf = io.StringIO()
	code = doctor.run_doctor(config.path, env=env, out=buf, **kw)
	return code, buf.getvalue()


def test_doctor_never_sends_keys_to_a_cleartext_remote_url(live):
	config, env, calls = live
	code, text = run_live(config, env, proxy_url="http://proxy.example.com:8888")
	assert code == 1 and "apiUrl" in text and "proxy-url" in text
	assert calls == []


def test_doctor_withholds_hindsights_own_key_from_remote_proxies(live):
	from omp_hindsight_guard.config import load_keys

	config, env, calls = live
	upstream = load_keys(config).upstream
	run_live(config, env, proxy_url="https://proxy.example.com")
	assert calls and all(key != upstream for _, key in calls)
	calls.clear()
	run_live(config, env, proxy_url="http://127.0.0.1:9")
	assert any(key == upstream for _, key in calls)  # on this machine the check still runs


# --- L10: importer edges ------------------------------------------------------------------------------------------


def test_a_cwd_with_a_nul_byte_routes_to_nothing_instead_of_aborting(tmp_path):
	banks = [("alpha", "~/work/a")]
	assert routing.route("/x/a\x00b", banks, tmp_path) == routing.Route(None, True)


def test_importance_is_redacted_like_every_other_field():
	secret = "sk-" + "Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56"
	raw = {
		"table": "working_memory",
		"id": "1",
		"content": "c",
		"source": "s",
		"timestamp": None,
		"created_at": None,
		"session_id": None,
		"importance": secret,
		"metadata_json": None,
		"superseded_by": None,
		"valid_until": None,
	}
	import datetime as dt
	from pathlib import Path

	row = im.build_row(
		"lbl-1",
		raw,
		Path("/h"),
		[],
		lambda p: None,
		redact_text,
		lambda t: [],
		dt.datetime.now(dt.timezone.utc),
	)
	assert secret not in (row.importance or "")
	assert "[REDACTED" in (row.importance or "")
