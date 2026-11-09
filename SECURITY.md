# Security policy

## Reporting a vulnerability

Please report security problems privately, not in a public issue. Use this repository's **Security tab → Report a
vulnerability** (GitHub private vulnerability reporting). Include the version (`omp-hindsight-guard --version`), your
platform, and the smallest input or configuration that shows the problem. Do not include real credentials; build a
fake one in the same shape.

You can expect an acknowledgement within a few days. This is a small project maintained by one person, so there is
no service-level promise, but reports that show a way to cross from one bank to another, to forward a request the
proxy should refuse, or to get a secret past the redactor in a shape it claims to handle are treated as the highest
priority.

Only the latest released version is supported while the project is `0.x`.

## What this tool is for, and what it is not

It reduces the chance that credentials end up in a Hindsight memory store, and it keeps one workspace's memories
from being read or written with another workspace's key. It is **not** a data-loss-prevention product and **not** a
sandbox. The full model is in [`docs/threat-model.md`](docs/threat-model.md).

## The limits of redaction, in writing

The redactor ([`src/omp_hindsight_guard/redact.py`](src/omp_hindsight_guard/redact.py)) replaces text that
*looks like* a secret with `[REDACTED:<kind>]` before it is stored. It cannot know what is secret; it recognises
shapes and contexts. Treat every memory bank as a place where some secrets may still be present.

**What it catches** (each has tests that build the fake secret at run time):

- token shapes that are secrets wherever they appear: AWS access key ids; GitHub, GitLab, Slack, Google, npm,
  Hugging Face, Stripe, Twilio, SendGrid, Mailgun, Linear, Notion and DigitalOcean tokens; `sk-` style API keys;
  JSON Web Tokens; Azure account keys; `Bearer <token>`; `Basic <base64 user:password>`; PEM private-key blocks
  (to the end of the text when the footer is missing); credentials inside URLs (`scheme://user:password@host`,
  `scheme://<key>@host`);
- assignments whose **name** says secret (key, secret, token, password, credential, dsn, auth, ...) and whose
  **value** looks like one: `.env` lines, quoted assignments in code, JSON and YAML (also JSON escaped inside a
  string), unquoted YAML values, **spaced unquoted `name = value` lines** (`~/.aws/credentials`, `.pypirc`,
  `.my.cnf`, TOML and INI; the value may carry a trailing `# comment`), `.npmrc` `_authToken=...` lines,
  `Authorization:` and other secret-named HTTP headers, URL query parameters whose **name** says secret
  (`access_token`, `refresh_token`, `id_token`, `X-Amz-Signature`, `X-Amz-Security-Token`, ..., any case), and
  `--password`/`--token`/`--secret`/`--api-key` command-line flags;
- values under a secret-named JSON key even when the value is a **list or an object** (`"tokens": ["..."]`), and
  **quoted** values in assignments: in those contexts punctuation such as `( ) [ ] { }` is an ordinary password
  character, so `"password": "Abc(123)xyz9"` is caught;
- an **identifier** (document id, tag, `types`, `entities[*].type`, ...) is refused, not stored, if any word that
  names a secret is directly followed (after `:`, `/`, `@` or spaces) by a value that looks like one:
  `password:<value>`, `note password: <value>`, `mnemopi:password:<value>`. This does not depend on the
  line-anchored rules that the rest of the text goes through. Token shapes inside tags and other identifiers are rewritten so
  they stay stable, but a **document id** that the token rules would change is refused, because the id is looked up
  later and must stay the one recorded. A document id that happens to contain a secret-named word followed by an ordinary-looking word
  (`session:token:abc123xy`) is refused too: the tool prefers refusing an id to storing a credential;
- the proxy's own keys and Hindsight's key, wherever they appear in a write body.

**What it does not catch:**

- a **bare password or secret in prose** ("the admin password is correct-horse-battery"), and anything else with
  no recognisable shape or name;
- a secret **split** across two fields, two messages or two requests;
- a secret hidden with **zero-width characters, homoglyphs or an extra layer of encoding** (base64 of a token, URL
  or hex encoding, reversed text);
- **short or low-variety values** under a secret name (`password = 12345`, `token: abc`): the value rules need a
  few character classes or length to avoid redacting ordinary code;
- **code-shaped passwords without a digit** in a quoted or JSON context: `"password": "correct_horse_battery"` is
  snake_case, and a snake_case or dotted value is treated as a reference to code (`get_token`, `settings.KEY`)
  unless it contains a digit (`correct_horse_7` is caught). A lowercase-words-and-underscores password is the
  residual gap of that rule;
- **unquoted** values that contain brackets (`password = Abc(123)xyz9` in a config file): an unquoted value with
  `( ) [ ] { }` is treated as code (`token = get_token()`, `key = a[0]`) and left alone. The importer's residual
  scan applies the same exemption, so it does not report them either;
- secrets in **JSON object keys** (only values and list items are scanned) and in **numbers or booleans**;
- secrets in **space-separated** config lines with no `=` or `:` (netrc `password hunter2`, `machine ... login ...`),
  in **multi-line or continued** values, and in values that **contain spaces**;
- a spaced `name = value` line is matched only when it is the whole line (plus an optional trailing comment); the
  same text inside a longer sentence or after other text on the line is not;
- **vendor tokens with no distinctive shape** and no secret-looking name nearby (Vercel, Cloudflare, Datadog keys,
  bare UUID tokens);
- a list item under an **ordinary** key name (`"notes": ["..."]`) is scanned as plain text without name context;
- URL parameters whose **name** gives no hint (`?s=...`);
- secrets inside **images**: base64 image data in message content is passed through byte for byte on purpose;
- anything **already stored** before the proxy was in the path, and anything a **model** writes into memory later
  from context the redactor never saw;
- **responses**: what Hindsight returns on read is not scanned.

**Things that can go wrong the other way:** ordinary text is occasionally replaced (a long random-looking
identifier next to the word `token`, for example), which changes what is stored. Code such as `token = get_token()`,
`api_key: str` or `KEY_PREFIX = "project:"` is deliberately left alone.

**Failing closed.** A write body that is not JSON is refused (`415`); a JSON string longer than 1,000,000
characters is refused (`413`) rather than scanned; identifiers and tags that contain anything beyond a restricted
alphabet are refused (`400`) rather than passed on unscanned; any unexpected error in the proxy before forwarding is
a `500` and nothing is sent upstream.

**Linear time.** Every pattern is written so that adversarial input cannot make it run super-linearly (the tests
check that doubling the input does not much more than double the work). That is a property of these patterns, not
a proof about every possible input.

**The residual scan.** `omp-hindsight-guard import` runs a second, stricter scan after redaction and refuses to send
when it still finds something that looks secret (long high-entropy runs, URL credentials, secret-named assignments).
It reports counts and offsets, never the text. It is a second opinion for a human to review, with its own false
positives and misses; `omp-hindsight-guard redact --fail-on-residual` applies it to any text.

**Practical advice:** keep real credentials out of the sessions you let omp remember; rotate any secret you find in
a bank (redaction after the fact does not un-store it); keep backups and exports as protected as the database.

## No warranty

This software is provided under the MIT licence, without warranty of any kind. Nothing in this repository claims
that redaction is complete.
