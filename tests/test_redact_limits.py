"""Properties of the redactor over many generated inputs, and the documented limits (SECURITY.md) as tests, so
the written limits cannot drift from the behaviour. Everything secret-looking is assembled at run time."""

import random
import string

import pytest

from omp_hindsight_guard.redact import RejectBody, TextTooLarge, redact_json, redact_text, residual_findings

PLANTED = {
	"aws": "AKIA" + "Q3EXAMPLE7KZ2M4P",
	"github": "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
	"gitlab": "glpat-" + "x9Yz8Wv7Ut6Sr5Qp4On3",
	"slack": "xoxb-" + "123456789012-abcdefABCDEF",
	"google": "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q",
	"jwt": "eyJhbGciOiJIUzI1NiJ9"
	+ ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
	+ ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
	"sk": "sk-" + "Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56",
}
FILLER = [
	"the build failed",
	"see https://example.com/a/b?x=1",
	"def f(token): return token",
	"KEY_PREFIX = 'project:'",
	"é ü 漢字 🙂",
	"\u200b",
	"-----",
	"a" * 70,
	"=",
	":",
	"{",
	"}",
	'"',
	"'",
	"\\",
	"\n",
	"\t",
	"mysql -u root",
	"Authorization:",
	"password",
	"--token",
	"?key=",
	"://",
	"@",
]
SAFE_BOUNDARY = [" ", "\n", "\t", ",", ";", "(", ")", "[", "]", "<", ">"]


def compose(rng):
	parts = [rng.choice(FILLER) for _ in range(rng.randint(0, 12))]
	return "".join(parts), parts


def test_random_text_never_crashes_and_stays_idempotent():
	rng = random.Random(20261109)
	for _ in range(3000):
		text, _ = compose(rng)
		out, counts = redact_text(text)
		again, more = redact_text(out)
		assert again == out and not more, (text, out)
		assert all(len(kind) > 0 for kind in counts)
		residual_findings(out)  # must not raise


def test_a_planted_token_never_survives_whatever_surrounds_it():
	rng = random.Random(7)
	for _ in range(1500):
		name = rng.choice(list(PLANTED))
		secret = PLANTED[name]
		left, _ = compose(rng)
		right, _ = compose(rng)
		text = f"{left}{rng.choice(SAFE_BOUNDARY)}{secret}{rng.choice(SAFE_BOUNDARY)}{right}"
		out, _ = redact_text(text)
		assert secret not in out, (name, text)


def test_random_json_keeps_its_shape_and_loses_planted_tokens():
	rng = random.Random(99)

	def build(depth):
		kind = rng.random()
		if depth > 3 or kind < 0.4:
			secret = rng.choice(list(PLANTED.values()))
			return f"{compose(rng)[0]} {secret} {compose(rng)[0]}"
		if kind < 0.7:
			return [build(depth + 1) for _ in range(rng.randint(0, 3))]
		return {
			rng.choice(["note", "content", "meta", "text", "items"]): build(depth + 1)
			for _ in range(rng.randint(0, 3))
		}

	def shape(v):
		if isinstance(v, dict):
			return {k: shape(x) for k, x in v.items()}
		if isinstance(v, list):
			return [shape(x) for x in v]
		return None

	def strings(v):
		if isinstance(v, str):
			yield v
		elif isinstance(v, list):
			for x in v:
				yield from strings(x)
		elif isinstance(v, dict):
			for x in v.values():
				yield from strings(x)

	for _ in range(400):
		body = {"items": [{"content": build(0), "metadata": build(1)}]}
		out, _ = redact_json(body)
		assert shape(out) == shape(body)
		assert not any(s in text for s in PLANTED.values() for text in strings(out))


@pytest.mark.parametrize("seed", range(5))
def test_random_bytes_as_text_never_crash(seed):
	rng = random.Random(seed)
	alphabet = string.printable + "éü漢🙂\u200b\u202e"
	for _ in range(300):
		text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 600)))
		try:
			redact_text(text)
		except TextTooLarge:
			pytest.fail("short text refused")


# --- the limits written in SECURITY.md, pinned so they stay true ------------------------------------------------


def test_a_bare_password_in_prose_is_not_caught():
	text = "the admin password is correct-horse-battery-staple, do not share"
	assert redact_text(text)[0] == text


def test_a_secret_split_across_fields_is_not_caught():
	secret = PLANTED["github"]
	out, _ = redact_json({"items": [{"content": secret[:20], "metadata": {"rest": secret[20:]}}]})
	assert out["items"][0]["content"] == secret[:20] and out["items"][0]["metadata"]["rest"] == secret[20:]


def test_a_secret_with_zero_width_characters_or_extra_encoding_is_not_caught():
	secret = PLANTED["github"]
	hidden = secret[:8] + "\u200b" + secret[8:]
	assert redact_text(f"token {hidden} here")[0] == f"token {hidden} here"
	import base64

	encoded = base64.b64encode(secret.encode()).decode()
	assert redact_text(f"blob {encoded}")[0] == f"blob {encoded}"


def test_short_low_variety_values_under_a_secret_name_are_not_caught():
	for text in ("password = 12345", "token: abc", "API_KEY=abcdef"):
		assert redact_text(text)[0] == text


def test_json_object_keys_and_non_strings_are_not_scanned():
	secret = PLANTED["aws"]
	out, counts = redact_json({"items": [{"content": "x", "metadata": {secret: "v", "pin": 1234567890}}]})
	assert secret in out["items"][0]["metadata"] and out["items"][0]["metadata"]["pin"] == 1234567890
	assert not counts


def test_image_data_passes_byte_for_byte():
	import base64

	data = base64.b64encode(PLANTED["aws"].encode() * 20).decode()
	block = {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": data}}
	out, counts = redact_json({"items": [{"content": [block], "document_id": "d"}]})
	assert out["items"][0]["content"][0] == block and not counts


def test_oversized_strings_are_refused_not_scanned():
	with pytest.raises(TextTooLarge):
		redact_text("a" * 1_000_001)
	with pytest.raises(RejectBody):
		redact_json({"tags": ["bad tag!"]})
