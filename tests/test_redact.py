import base64
import os
import time

import pytest

from omp_hindsight_guard.redact import (
	MAX_TEXT_CHARS,
	RejectBody,
	TextTooLarge,
	redact_json,
	redact_text,
	redact_tokens,
	residual_findings,
)

# Fake credentials in the real shapes. Built by concatenation so this file never holds a scanner-bait literal.
AWS = "AKIA" + "Q3EXAMPLE7KZ2M4P"
GH_PAT = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
GH_FINE = "github_pat_" + "11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz"
GL_PAT = "glpat-" + "x9Yz8Wv7Ut6Sr5Qp4On3"
SK_PROJ = "sk-proj-" + "Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56"
SK_ANT = "sk-ant-api03-" + "Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0Pp"
SLACK = "xoxb-" + "123456789012-abcdefABCDEF"
GOOGLE = "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"
JWT = "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0" + ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
# A fake PEM block, assembled so no scanner sees a begin/end pair in this file.
PEM = (
	"-----BEGIN OPENSSH " + "PRIVATE KEY-----\n"
	"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
	"-----END OPENSSH " + "PRIVATE KEY-----"
)

# Fake values for assignments. Neutral names, so a secret scanner does not mistake this file for a leak; the
# redactor still sees the name next to the value in the test inputs, which are f-strings built from these.
V_ABC = "abc123def456" + "ghi"
V_QW = "Qw3rty9876" + "abc"
V_CS = "q9W8e7R6" + "t5Y4"
V_HEX = "9f8e7d6c5b4a" + "39281706f5e4d3c2b1a0"
V_QQ = "Qq9Ww8Ee7Rr6"
V_B64 = "dXNlcjpo" + "dW50ZXIyMg=="
V_TOK = "abcdefgh" + "12345678"
V_XAPI = "abc123secret" + "XYZ"
V_PP = "Pp0Oo9Ii8Uu7"
V_RR = "Rr5Tt6Yy7Uu8"
V_GHCLI = "abcdEF" + "123456"
V_BEARER = "abcDEF123456" + "ghiJKL789mno"


def redacted(text):
	out, counts = redact_text(text)
	return out, dict(counts)


@pytest.mark.parametrize(
	("text", "secret", "kind"),
	[
		(f"aws id {AWS} here", AWS, "aws-access-key"),
		(f"token: {GH_PAT}", GH_PAT, "github-token"),
		(f"{GH_FINE} was pasted", GH_FINE, "github-token"),
		(f"use {GL_PAT} for the api", GL_PAT, "gitlab-token"),
		(f"SK_PROJ={SK_PROJ}", SK_PROJ, "api-key"),
		(f"the key is {SK_ANT}.", SK_ANT, "api-key"),
		(f"slack {SLACK}", SLACK, "slack-token"),
		(f"maps {GOOGLE}", GOOGLE, "google-api-key"),
		(f"jwt {JWT}", JWT, "jwt"),
		(f"key:\n{PEM}\nafter", "b3BlbnNzaC1rZXktdjEAAAAA", "private-key"),
		(
			f"curl -H 'Authorization: Bearer {V_BEARER}'",
			V_BEARER,
			"bearer-token",
		),
	],
)
def test_token_shapes_are_redacted(text, secret, kind):
	out, counts = redacted(text)
	assert secret not in out
	assert counts.get(kind, 0) >= 1, counts
	assert f"[REDACTED:{kind}]" in out


def test_truncated_private_key_is_redacted_to_the_end():
	out, counts = redacted("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7x\nmore")
	assert "MIIEowIBAAKCAQEA7x" not in out and counts["private-key"] == 1


def test_url_credentials_keep_user_and_host():
	out, counts = redacted("DATABASE_URL is postgres://app:S3cretPw9@db.example:5432/app")
	assert "S3cretPw9" not in out
	assert "postgres://app:[REDACTED:url-credentials]@db.example:5432/app" in out
	assert counts == {"url-credentials": 1}


@pytest.mark.parametrize(
	("text", "secret"),
	[
		(f"API_KEY={V_ABC}", V_ABC),
		('export GITHUB_TOKEN="Zq81mmPa0x"', "Zq81mmPa0x"),
		("DB_PASSWORD=hunter22", "hunter22"),
		(f"API_KEY={V_ABC} npm start", V_ABC),
		(f"cd app; GITLAB_TOKEN={V_QW} make deploy", V_QW),
		(
			"  aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY",
			"wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY",
		),
		("SENTRY_DSN=https://abc123@o1.ingest.sentry.example/42", "abc123@o1"),
		('password = "Tr0ub4dor&3"', "Tr0ub4dor&3"),
		(f'{{"client_secret": "{V_CS}"}}', V_CS),
		("db:\n  password: s3cretValue9\n", "s3cretValue9"),
		(f"apiToken: {V_HEX}", V_HEX),
	],
)
def test_secret_assignments_are_redacted(text, secret):
	out, counts = redacted(text)
	assert secret not in out, out
	assert sum(counts.values()) >= 1


# Ordinary code, prose and identifiers: nothing here may be redacted or reported.
ORDINARY = [
	"token = get_token()",
	"password_field = forms.CharField(max_length=128)",
	"def f(api_key: str, token: str | None = None):",
	'KEY_PREFIX = "project:"',
	"const tokenizer = new AutoTokenizer(config);",
	'auth = request.headers["Authorization"]',
	"monkey_key_id = 3",
	"TOKEN_TYPE=bearer",
	"apiToken: ${HINDSIGHT_API_TOKEN}",
	"apiToken: <YOUR_KEY>",
	"password: changeme",
	"commit 67edf5f2c1d9a8b7e6f5a4b3c2d1e0f9a8b7c6d5 fixed the bug",
	"uuid 550e8400-e29b-41d4-a716-446655440000 and sha256 fd170af576ab82de03047e1122eafd474d8fcfd4",
	"run the task-runner, then disk-usage, then sk-learn-compatible-estimators",
	"clone https://git@example.com/org/repo.git or https://user@host/path",
	"The Authorization header uses the Bearer authentication-scheme-description.",
	"secret_santa: the team party is on Friday",
	"if not api_key:\n    raise ValueError('missing key')",
	"export PATH=$HOME/.local/bin:$PATH",
	"keys = sorted(bank_keys.items())",
	"client = Client(api_key=settings.SERVICE_API_KEY)",
	"run(url, token=self.token, auth=auth_tuple)",
	"API_KEY=$SERVICE_API_KEY npm start",
	"SECRET_KEY=DJANGO_SECRET_KEY python manage.py check",
	"see https://docs.python.org/3/library/re.html?highlight=key#module-re and https://example.com:8080/a/@me",
	"commits 67edf5f and 9fceb02d0ae598e95dc970b74767f19372d61af8",
	"ssh -p 2222 deploy@host",
	"psql -h db.example -p 5432 -U app",
	'curl -H "Content-Type: application/json" -H "Accept: */*" https://api.example.com/v1/items',
	"# API keys\n\n- Set `API_KEY` in `.env`.\n- **Token**: use the `gh` CLI.\n- [docs](https://x.dev/auth)",
	'headers = {"Authorization": f"Bearer {token}"}',
	'url = f"https://api.example.com/v1/x?token={token}&page={page}"',
	'print(f"token={token} api_key={api_key}")',
	"basic authentication is enabled; the basic idea is simple",
	"mytool --token $GITHUB_TOKEN --password <password>",
	"mysql -u root -p app_db",
]


@pytest.mark.parametrize("text", ORDINARY)
def test_ordinary_code_and_prose_untouched(text):
	out, counts = redacted(text)
	assert out == text, out
	assert counts == {}


def test_extra_secrets_exact_match():
	key = "f00dfeed" * 8
	out, counts = redact_text(f"proxy key {key} leaked", [key])
	assert key not in out and counts["proxy-key"] == 1


def test_idempotent():
	once, _ = redact_text(f"API_KEY={V_ABC} and {GH_PAT}")
	twice, counts = redact_text(once)
	assert twice == once and not counts


# Provider and context shapes. Fake values, assembled at runtime.
HEX32 = "0123456789abcdef" * 2
F3_CASES = [
	# JSON escaped inside a string (tool-call arguments), single and double escaping.
	('{\\"password\\":\\"hunter2Xyz\\"}', "hunter2Xyz", "assignment"),
	('{\\\\\\"password\\\\\\":\\\\\\"hunter2Xyz\\\\\\"}', "hunter2Xyz", "assignment"),
	('args: "{\\"client_secret\\": \\"q9W8e7R6t5Y4\\"}"', "q9W8e7R6t5Y4", "assignment"),
	# Query-string / URL parameters.
	(
		"GET https://api.example.com/v1/me?access_token=AbC123dEf456GhI789&page=2",
		"AbC123dEf456GhI789",
		"url-param",
	),
	(
		"https://bucket.s3.amazonaws.com/f?X-Amz-Date=1&signature=9aB8cD7eF6gH5iJ4",
		"9aB8cD7eF6gH5iJ4",
		"url-param",
	),
	("https://maps.example.com/x?apikey=Zz11Yy22Xx33&sig=Ww44Vv55Uu66", "Zz11Yy22Xx33", "url-param"),
	(f"callback?a=1&amp;client_secret={V_QQ}", V_QQ, "url-param"),
	# URL userinfo: empty user, '/' in the password, key-only DSN.
	("REDIS_URL is redis://:S3cretPass@cache:6379/0", "S3cretPass", "url-credentials"),
	("postgres://app:pa/ss9Word@db.example/app", "pa/ss9Word", "url-credentials"),
	(f"sentry at https://{HEX32}@o1.ingest.sentry.example/1", HEX32, "url-credentials"),
	# Authorization schemes and headers.
	(f'curl -H "Authorization: Basic {V_B64}" https://x', V_B64, "basic-auth"),
	("proxy sent basic YWRtaW46UzNjcmV0IQ== upstream", "YWRtaW46UzNjcmV0IQ==", "basic-auth"),
	(f"Authorization: Token {V_TOK}", V_TOK, "authorization"),
	('{\\"Authorization\\": \\"Token Kk1Ll2Mm3Nn4\\"}', "Kk1Ll2Mm3Nn4", "authorization"),
	(f'curl -H "X-Api-Key: {V_XAPI}" https://x', V_XAPI, "header"),
	(f"curl --header 'apikey: {V_PP}' https://x", V_PP, "header"),
	(f"Private-Token: {V_RR}", V_RR, "header"),
	# CLI flags.
	("mytool login --password hunter22 --verbose", "hunter22", "cli-flag"),
	("mytool login --password=hunter22", "hunter22", "cli-flag"),
	(f"gh auth --token {V_GHCLI}", V_GHCLI, "cli-flag"),
	("vault write --secret 'Qq12345678' x", "Qq12345678", "cli-flag"),
	("client --api-key Zz9988776655 run", "Zz9988776655", "cli-flag"),
	("mysql -h db -u root -pS3cret app", "S3cret", "cli-flag"),
	("mysqldump -u root -p'Hu7nter' app", "Hu7nter", "cli-flag"),
	# dotenv values containing '#', ';' and '"'.
	("PASSWORD=ab;c9Xq7Zr", "c9Xq7Zr", "env-assignment"),
	("API_KEY=abc#def123ghi", "def123ghi", "env-assignment"),
	('DB_PASSWORD=Pa"ss9word', "ss9word", "env-assignment"),
	# Provider shapes.
	(f"twilio SK{HEX32} and", f"SK{HEX32}", "twilio-key"),
	(f"account AC{HEX32}", f"AC{HEX32}", "twilio-key"),
	(
		"SG." + "aB1cD2eF3gH4iJ5kL6mN7o" + "." + "pQ8rS9tU0vW1xY2zA3bC4dE5fG6hI7jK8lM9nO0pQ1r",
		"pQ8rS9tU0vW1",
		"sendgrid-key",
	),
	(f"mailgun key-{HEX32}", HEX32, "mailgun-key"),
	("linear lin_api_" + "Ab1Cd2Ef3Gh4" * 4, "Ab1Cd2Ef3Gh4", "linear-key"),
	("notion ntn_" + "Ab1Cd2Ef3Gh4" * 4, "Ab1Cd2Ef3Gh4", "notion-token"),
	("notion secret_" + "Ab1Cd2Ef3Gh4" * 3 + "Ij5Kl6M", "Ab1Cd2Ef3Gh4", "notion-token"),
	("do dop_v1_" + HEX32 * 2, HEX32, "digitalocean-token"),
	(
		"DefaultEndpointsProtocol=https;AccountName=x;AccountKey="
		+ "Ab1+Cd2/" * 11
		+ "==;EndpointSuffix=core",
		"Ab1+Cd2/",
		"azure-key",
	),
]


@pytest.mark.parametrize(("text", "secret", "kind"), F3_CASES)
def test_context_and_provider_shapes_are_redacted(text, secret, kind):
	out, counts = redacted(text)
	assert secret not in out, out
	assert counts.get(kind, 0) >= 1, counts


def test_redaction_keeps_surrounding_text():
	out, _ = redacted("redis://:S3cretPass@cache:6379/0 and ?access_token=AbC123dEf456GhI789&page=2")
	assert (
		out
		== "redis://:[REDACTED:url-credentials]@cache:6379/0 and ?access_token=[REDACTED:url-param]&page=2"
	)
	out, _ = redacted('{\\"password\\":\\"hunter2Xyz\\"}')
	assert out == '{\\"password\\":\\"[REDACTED:assignment]\\"}'
	out, _ = redacted("cd app; PASSWORD=ab;c9Xq7Zr make")
	assert out == "cd app; PASSWORD=[REDACTED:env-assignment] make"


def test_idempotent_over_new_shapes():
	once, _ = redact_text("\n".join(text for text, _, _ in F3_CASES))
	twice, counts = redact_text(once)
	assert twice == once and not counts


def test_redact_tokens_skips_name_based_rules():
	out, counts = redact_tokens(f"project:API_KEY={V_ABC} {GH_PAT}")
	assert V_ABC in out and GH_PAT not in out
	assert dict(counts) == {"github-token": 1}


def test_text_too_large():
	assert issubclass(TextTooLarge, RejectBody) and issubclass(RejectBody, ValueError)
	big = "a" * (MAX_TEXT_CHARS + 1)
	for fn in (redact_text, redact_tokens):
		with pytest.raises(TextTooLarge):
			fn(big)
	with pytest.raises(TextTooLarge):
		redact_json({"items": [{"content": big}]})
	redact_text("a" * MAX_TEXT_CHARS)


SMALL, LARGE = 100_000, 200_000


def adversarial(n):
	"""Inputs that make a backtracking or quadratic pattern blow up, each about n characters long."""
	return {
		"spaces": lambda: " " * n,
		"tabs": lambda: "\t" * n,
		"spaces-and-tabs": lambda: " \t" * (n // 2),
		"indented-names": lambda: (" " * 60 + "a") * (n // 61),
		"dots": lambda: "a." * (n // 2),
		"equals": lambda: "=" * n,
		"colons": lambda: ":" * n,
		"base64": lambda: base64.b64encode(os.urandom(n * 3 // 4)).decode().rstrip("="),
		"query": lambda: "?a=" * (n // 3),
		"query-names": lambda: "?key=" * (n // 5),
		"schemes": lambda: "a://x:" * (n // 6),
		"dashes": lambda: "a-" * (n // 2),
		"assignments": lambda: " A=x;" * (n // 5),
		"escaped": lambda: '\\"' * (n // 2),
		"mysql": lambda: "mysql " * (n // 6),
		"authorization": lambda: "Authorization: Bearer " * (n // 22),
		"pem": lambda: "-----BEGIN " * (n // 11),
		"yaml-names": lambda: ("a" * 60 + ":") * (n // 61),
		"spaced-assignments": lambda: ("password = " + "a" * 30 + "\n") * (n // 42),
		"spaced-no-newline": lambda: "password = " + "a" * n,
		"spaced-long-names": lambda: ("a" * 120 + "  =  x y\n") * (n // 130),
		"spaced-comments": lambda: ("token = abc123XYZ " + "# c " * 40 + "\n") * (n // 200),
		"url-param-names": lambda: ("&" + "a" * 59) * (n // 60),
		"url-param-pairs": lambda: ("&token=" + "x" * 10) * (n // 17),
		"npmrc": lambda: "/:_" * (n // 3),
		"residual-spaced": lambda: ("secret_" + "a" * 100 + " = ") * (n // 110),
	}


def cpu_seconds(text):
	"""Best of seven CPU times for redacting and scanning text (CPU time, so a busy machine does not count)."""
	best = float("inf")
	for _ in range(7):
		start = time.process_time()
		redact_text(text)
		residual_findings(text)
		best = min(best, time.process_time() - start)
	return best


@pytest.mark.parametrize("name", list(adversarial(10)))
def test_adversarial_input_scales_linearly(name):
	"""Doubling the input must not much more than double the work (a quadratic pattern would quadruple it).

	A ratio (a quadratic pattern gives 4, so 3.5 still catches it), not a wall-clock bound: the absolute speed depends on the machine, the growth does not. Below
	0.02 s timer noise dominates the ratio, so only the loose absolute ceiling applies there.
	"""
	small = cpu_seconds(adversarial(SMALL)[name]())
	large = cpu_seconds(adversarial(LARGE)[name]())
	assert large < 15, f"{name}: {large:.1f} s for {LARGE} characters"
	if small >= 0.02:
		assert large / small < 3.5, f"{name}: {small:.3f} s -> {large:.3f} s for 2x the input"


# residual_findings
PLANTED = "q8Zr2LmX0vB7nT4yW1cK9pD6sF3hJ5gA"


@pytest.mark.parametrize(
	("text", "kind"),
	[
		(f"the log line had {PLANTED} in it", "high-entropy"),
		("connect to amqp://guest:hunter22@rabbit/vhost", "url-credentials"),
		("password: S0meth1ngLong", "secret-assignment"),
		('{"api_key": "Zq81mmPa0x77"}', "secret-assignment"),
	],
)
def test_residual_findings_report_leftovers(text, kind):
	found = residual_findings(text)
	assert kind in [k for k, _ in found], found
	assert all(isinstance(offset, int) and 0 <= offset < len(text) for _, offset in found)


@pytest.mark.parametrize("text", ORDINARY)
def test_residual_findings_quiet_on_ordinary_text(text):
	assert residual_findings(text) == []


def test_residual_findings_quiet_after_redaction():
	text = "\n".join(t for t, _, _ in F3_CASES) + f"\n{GH_PAT} {AWS} {JWT} postgres://app:S3cretPw9@db/x"
	out, _ = redact_text(text)
	assert residual_findings(out) == [], [out[o : o + 40] for _, o in residual_findings(out)]
	marks_and_ids = (
		"[REDACTED:github-token] [REDACTED:url-credentials] [REDACTED:assignment]\n"
		"git 67edf5f2c1d9a8b7e6f5a4b3c2d1e0f9a8b7c6d5 uuid 550e8400-e29b-41d4-a716-446655440000\n"
		"sha256 " + "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	)
	assert residual_findings(marks_and_ids) == []


# redact_json
def test_redact_json_identifier_positions_get_token_rules_only():
	body = {
		"async": True,
		"document_tags": ["source:omp"],
		"items": [
			{
				"content": f"user pasted {AWS}",
				"context": "omp",
				"document_id": "sess-1",  # a token-shaped id is refused, not rewritten: see test_review5_fixes
				"timestamp": "2026-11-09T10:00:00Z",
				"tags": ["project:acme-app", "leak:" + GH_PAT],
				"metadata": {"session_id": "abc", "password": "hunter2Value"},
				"entities": [{"text": f"key {AWS}", "type": "PERSON"}],
			}
		],
	}
	out, counts = redact_json(body)
	item = out["items"][0]
	assert AWS not in item["content"] and AWS not in item["entities"][0]["text"]
	assert item["document_id"] == "sess-1"
	assert item["tags"] == ["project:acme-app", "leak:[REDACTED:github-token]"]
	assert item["timestamp"] == "2026-11-09T10:00:00Z" and item["entities"][0]["type"] == "PERSON"
	assert item["metadata"] == {"session_id": "abc", "password": "[REDACTED:assignment]"}
	assert out["async"] is True and out["document_tags"] == ["source:omp"]
	assert counts["aws-access-key"] == 2 and counts["assignment"] == 1 and counts["github-token"] == 1


def test_redact_json_identifier_names_elsewhere_are_fully_redacted():
	body = {
		"items": [
			{
				"content": "x",
				"metadata": {"data": GH_PAT, "type": f"key {AWS}", "id": f"API_KEY={V_ABC}"},
			}
		],
		"nested": {"id": f"API_KEY={V_ABC}", "data": {"type": AWS}},
		"trigger": {"mode": "on_retain", "note": f"API_KEY={V_ABC}"},
	}
	out, _ = redact_json(body)
	meta = out["items"][0]["metadata"]
	assert meta["data"] == "[REDACTED:github-token]" and AWS not in meta["type"]
	assert meta["id"] == "API_KEY=[REDACTED:env-assignment]"
	assert out["nested"] == {
		"id": "API_KEY=[REDACTED:env-assignment]",
		"data": {"type": "[REDACTED:aws-access-key]"},
	}
	assert out["trigger"] == {"mode": "on_retain", "note": "API_KEY=[REDACTED:env-assignment]"}


def test_redact_json_name_based_rules_skip_identifier_positions():
	body = {"id": "model:api-key-1", "types": ["world", "experience"], "budget": "mid", "tags_match": "any"}
	out, counts = redact_json(body)
	assert out == body and not counts


@pytest.mark.parametrize(
	"body",
	[
		{"items": [{"content": "x", "document_id": f"sess\nAPI_KEY={V_ABC}"}]},
		{"items": [{"content": "x", "document_id": ""}]},
		{"items": [{"content": "x", "document_id": "a" * 201}]},
		{"items": [{"content": "x", "tags": ["ok", "bad{tag}"]}]},
		{"items": [{"content": "x", "tags": [3]}]},
		{"items": [{"content": "x", "tags": "project:x"}]},
		{"tags": ['password="hunter2Value"']},
		{"document_tags": ["a\tb"]},
		{"id": "model?id=1"},
		{
			"items": [
				{
					"content": [
						{"type": "image", "source": {"type": "base64", "media_type": "text/x", "data": ""}}
					]
				}
			]
		},
		{
			"items": [
				{
					"content": [
						{
							"type": "image",
							"source": {"type": "base64", "media_type": "image/png", "data": "a b!"},
						}
					]
				}
			]
		},
	],
)
def test_redact_json_rejects_invalid_identifiers(body):
	with pytest.raises(RejectBody):
		redact_json(body)


def test_redact_json_preserves_image_blocks():
	data = base64.b64encode(b"AKIA" + os.urandom(3000) + AWS.encode()).decode()
	block = {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": data}}
	text_block = {"type": "text", "text": f"see {AWS}"}
	body = {"items": [{"content": [text_block, block], "document_id": "doc-1"}]}
	out, counts = redact_json(body)
	content = out["items"][0]["content"]
	assert content[1] == block and content[1]["source"]["data"] is data
	assert content[0] == {"type": "text", "text": "see [REDACTED:aws-access-key]"}
	assert dict(counts) == {"aws-access-key": 1}
