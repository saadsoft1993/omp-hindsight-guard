# Threat model

Written for someone deciding whether to trust this tool, and for a reviewer. It describes what the tool defends,
against whom, what it does not defend, and where each control lives and is tested. File names are under
`src/omp_hindsight_guard/` and `tests/`.

## 1. What is being protected

| Asset | Why it matters |
|---|---|
| Memory banks in Hindsight | They hold what your coding sessions learned. One workspace's memories (for example a client's) must not be read or changed with another workspace's credentials. |
| Secrets that appear in session text | omp retains conversation turns automatically and does not redact them; a pasted token would be stored and recalled into later sessions. |
| Bank keys, the upstream key, overlays | Whoever holds a bank key can read and write that bank. The upstream key is Hindsight's own key and can reach every bank and every route. |
| Hindsight server and database | Reached only through the proxy; an unrestricted route would allow configuration changes, deletes and unredacted writes. |

## 2. Who might attack, and from where

| Actor | Capability assumed |
|---|---|
| **A client holding one bank's key** (omp in workspace A, or a script that has that key) | Can send any HTTP request to the proxy. Wants another bank's data, an unredacted write, a route outside the list, or Hindsight's admin surface. |
| **A network attacker** between a remote client and the proxy | Reads or alters traffic, if the operator exposed the proxy without TLS. |
| **A malicious or cloned repository** | Ships a `.omp/config.yml` and files that sessions read. Wants a session's key or transcripts to reach a server it names. |
| **Another local user** on a shared machine | Reads files and processes it is permitted to read. |
| **A same-user process** (any program you run) | Everything you can do. **Out of scope**; see section 5. |
| **Hostile text in memory** | Anything stored can be recalled into a later prompt. Out of scope for this tool; it is omp's and the model's problem (omp injects recall as background context, not instructions). |

## 3. Controls, with where they live

### 3.1 The proxy refuses by default (`proxy.py`, `tests/test_proxy.py`)

- **Route allow-list.** Only the (method, path, query names) triples in `ROUTES` are forwarded, always under
  `/v1/default/banks/<the key's bank>`. Today: create/update the bank's missions, retain, recall, reflect, list
  memories, list/get documents, list/get/create/refresh mental models and their history, list/get operations. Every
  other method and path, including DELETE, PATCH, configuration, webhooks, directives, `/docs`, `/openapi.json`,
  `/metrics`, `/version`, `/mcp` and other banks, is `404`.
- **Bank update body.** A `PUT` on the bank accepts only `reflect_mission` and `retain_mission`.
- **Queries** are accepted on `GET` only, with per-route names and a 200-character value limit.
- **Strict target parsing.** The raw request target must start with `/`, contain no control characters,
  backslash, `#` or whitespace, no `;`, no `//`, no `..`, no encoded `/`, `\` or `.`; each path segment is
  percent-decoded **exactly once**, and escapes are accepted only for unreserved characters inside an id. The
  request that is forwarded is **rebuilt** from the parsed parts, never relayed. Tests include double-encoding,
  encoded traversal, absolute-form targets, `;` parameters and case tricks.
- **Key pinned to a bank.** The bank is derived from the key and a path naming any other bank is `404`, not `403`,
  so the existence of other banks is not revealed. The key comparison is constant time (`hmac.compare_digest`) and
  **every** key is compared on every request, so the time taken does not reveal which bank matched.
- **Fail closed.** No key, an unknown key, or Hindsight's own key is `401`. A write body that is not JSON is
  `415`; invalid or too deeply nested JSON is `400`; a string over 1,000,000 characters is `413`; a body over
  32 MiB is `413`; chunked request bodies are `411`; an unexpected exception before forwarding is `500` with nothing
  sent upstream; an unreachable upstream is `502`. Error responses close the connection.
- **Upstream key replaced.** The client's `Authorization` is dropped and Hindsight's key is added; only
  `Content-Type: application/json` and `Accept` are set on the forwarded request. No client header is relayed.
- **Redaction of every write body** (`redact.py`): every string, including list items and metadata values, goes
  through the token and name rules; identifier fields (document ids, tags and similar) get the token rules only and
  must match a restricted alphabet; the proxy's own keys are removed wherever they appear. Limits of the patterns
  are in [`SECURITY.md`](../SECURITY.md).
- **Logs** carry method, bank, route class, status and the count of redactions only; never bodies, headers,
  queries, ids or keys (`tests/test_proxy.py::test_log_lines_carry_no_secrets_or_bodies`).
- **Listening.** Loopback unless `proxy.allow_remote_listen` is set; the upstream must be loopback `http`.

### 3.2 Keys and files (`config.py`, `overlays.py`, `tests/test_config.py`, `tests/test_overlays.py`)

- Key files must be regular files owned by you, mode 0600, 32-512 printable characters without quote, backslash
  or space, in a directory that is yours and not writable by group or other, and every key must differ. Error
  messages never contain a key.
- **banks.json is trusted input and is checked as such when it is opened**: a regular file owned by you, not
  writable by group or other, in a directory with the same properties. Whoever can write it can point the proxy's
  upstream at a listener of their own and receive Hindsight's key, so a loose file is refused, not just reported by
  `doctor`. Existing configuration, overlay and state directories are rejected, not reused, when they are not yours
  or are group/other-writable. Every such path is walked **lexically, component by component, with lstat**, the way
  the kernel resolves it: every directory passed through (including the one that holds a symlink, and the ones a
  symlink leads into) must be yours or root's and not group/other-writable unless sticky, and every symlink must be
  yours or root's. A group is never assumed to be private. Resolving the path first and checking the target's parents
  would lose the directory that controls an intermediate symlink. `trustwalk.py` is the one implementation of that walk, shared by the configuration loader, the importer's overlay
  read, the shell hook helper, `backup.sh` and `outbox-check.sh`; it reads symlink targets exactly (no newline
  trimming), follows `..` the way the kernel does (from the real directory reached so far), and allows up to 40
  links. On top of the mode bits it inspects **ACLs**: on macOS through `ls -le`, on Linux through the POSIX ACL
  attribute. An ACL entry that lets another principal write to a checked directory or file makes it untrusted, and
  so does one that lets another principal read a file that holds a secret (a key file, an overlay); deny entries are
  harmless; an ACL that cannot be inspected is not trusted. A path that fails the walk is treated as unknown
  configuration (a notice and an unchanged launch, or a refusal with `OMP_HINDSIGHT_GUARD_ON_DOWN=block`) and the
  cache is not used.
- The configuration directory, overlay directory and state directory are created 0700; overlays, `routes.tsv` and
  the ledger are written atomically as 0600. An overlay directory is reused only if it is not a symlink and holds
  nothing but overlays this tool wrote (marker line), `routes.tsv` and its own temporary files, and a `<bank>.yml`
  that is not ours is never replaced.
- Roots are compared the way routing compares them (symlinks resolved, case folded): a root that resolves to `/` or
  your home directory is refused, and two banks cannot own the same directory under different spellings. A root may
  not contain `.`, `..` or empty components or non-ASCII characters, because each launcher resolves a root with its
  own shell (the folding of non-ASCII case differs between zsh, bash and fish, and `..` through a folder that does
  not exist is resolved by Python but not by bash): only a spelling every launcher reduces to the same directory is
  accepted, and `tests/test_review3_hooks.py` runs the same directories through Python and every launcher. At run
  time two banks matching equally well select neither (no choice by file order).
- Overlays contain a key and are read by omp. The overlay URL must be `https://`, or `http://` to this machine only,
  with no whitespace or control characters (it is written as a quoted YAML string), so the key never crosses a
  network in clear text. The importer re-checks this, refuses overlays that are not 0600, not owned by you, or a
  symlink, and refuses an overlay whose `bankId` is not the bank it is about to send to.
- The hooks pass an overlay to omp as a file path (`--config`) and remove `PI_CONFIG_FILES` from omp's environment
  (only when an overlay applies); the key is not exported, so omp's tool subprocesses do not inherit it.

### 3.3 Isolation check (`doctor.py`, `tests/test_doctor.py`)

`omp-hindsight-guard doctor` tests the **running** proxy: no key is `401` and, for a proxy on this machine,
Hindsight's own key is `401` on every bank (a remote proxy is never sent Hindsight's key: that probe is skipped, the
report says so, and the isolation line does not claim it); each bank's key reads its own bank (`200`), gets `404` on
every other configured bank, on an unconfigured bank name, and on `/docs`. It fails on a proxy that checks no keys
(tested by pointing it at the bare upstream) and on a bank missing from the proxy. It prints no key. When nothing listens (connection refused) at the built-in default `http://127.0.0.1:8888` and no
`--proxy-url` was given, it prints a warning that says no proxy answered and that the isolation checks were not run,
and exits `0`: the warning is not evidence that isolation holds. Any other unreachable or badly answering proxy fails. With
`--backup-dir` it fails when the newest dump is too old, when a bank's newest export is older than 8 days, and, once
backups began (the date `backup.sh` recorded once in `.first-run`, else the oldest dump still there) more than 8 days
ago, when a bank has no export at all (until then it only warns).

### 3.4 The importer (`importer.py`, `tests/test_importer.py`)

Reads omp's local memory through a read-only SQLite backup into a private temporary snapshot; prints counts and ids
only; refuses to send unless `--confirm` equals the digest of exactly what would be sent; writes the redacted items
to a 0600 file first; refuses when the residual scan finds something, when the ledger says a **source row** already
went to a different bank, or when two documents would collide; never follows a redirect (so the bearer is never
re-sent elsewhere). Rows outside every root, rows without a working directory that cannot be placed unambiguously,
rows whose working directory **no longer exists** (they are placed only by today's roots, which nobody can check
against where they were written) and excluded labels are never sent without `--include-review`; a deleted folder
is also never used as evidence for routing the rows that have no folder at all.

- **Cross-bank content: a policy, not an isolation guarantee.** Text that is the same in two banks is allowed when
  the rows are distinct source rows (each is its own memory, routed by its own folder), and is **listed**
  (`content-also-in:` lines) against both the ledger and the other documents of the same run. The rule is the same
  whether the other copy was sent earlier or is in this batch. A source row that moves banks is refused. If you
  want every text that appears in two banks stopped, read those lines before `--send`: the tool does not stop it.
- **One import at a time**: the ledger is locked (`flock`) for the whole `--send` or `--reconcile`, and read after the
  lock is taken, so a second import checks against what the first recorded.
- **The destination is written down before sending, and only the server's word erases it.** Each batch is reserved
  in the ledger (`pending`) before its POST. Only a refusal the server makes before storing anything (400, 401, 403,
  404, 405, 411, 413, 414, 415, 422, 429, 431) releases it (validation, authentication, routing and size refusals). A
  5xx (the proxy answers 502 when Hindsight took the write and dropped the connection; a 501 is also kept, because
  the proxy forwards the server's own), a 408, a redirect, a timeout or a crash prove nothing, so the reservation
  stays, and reserved rows count as already sent for every isolation check: an interrupted send cannot be repeated
  to a different bank. A document that is still unresolved is **never sent again** (`held_unresolved=` in the
  report): a second attempt would overwrite the evidence of the first. A failed or cancelled operation moves the
  document to `failed`: offered again, to the same bank only, because the document may exist there anyway.
- **Accepted is not synchronised.** Requests are asynchronous; a 2xx only means the server queued them. A reply with
  no usable operation id proves nothing either (synchronous completion is never inferred): the rows stay
  `unconfirmed`. Rows count as synced (`--only-new`, `--count-unsynced`) only when every operation reads
  `completed`, or when the document itself is read back (`GET .../documents/<id>`) with the expected content. That
  second path settles operations the server has pruned (`not_found`: `HINDSIGHT_API_OPERATION_RETENTION_DAYS` above
  0) and replies without ids. An unconfirmed document is printed, makes the exit status 1, and stays pending;
  `--reconcile --drop-unknown` is the one way to forget a destination (unconfirmed and failed records; never an
  operation that is still open), meant for after you looked at the server yourself. Operation statuses
  (`pending`, `processing`, `completed`, `failed`, `cancelled`, `not_found`) and the retain reply fields
  (`operation_id`, `operation_ids`) are the ones in Hindsight 1.2.0's source, and were checked against a live Hindsight 1.2.0 server
  (macOS, scratch banks): retains through the proxy and `--send --confirm` reached `completed`; after a finished operation's row was
  deleted from the server's operation table the operation read HTTP 200 with `status: not_found`, and `--reconcile` settled the
  document through the document read-back (`present (not_found)`).
- Overwriting a document with other content removes the old content's entry, and a content entry is trusted only if
  its document still holds that content.

### 3.5 Shell hooks and the shim (`hooks/`, `hookpick.py`, `tests/test_hook.py`)

Opt-in. The zsh, bash and fish functions and the PATH shim are thin: each calls `omp-hindsight-guard-pick`, a Python
helper that runs in the folder omp is started in and prints the overlay path (empty: run omp unchanged) or exits 75
(refuse). Everything that needs care is therefore written once: the routing table is parsed strictly (exactly one
tab per row, a valid bank name, an absolute or `~/` root with no control character, valid UTF-8; a comment or an
empty line is skipped; anything else is a malformed entry), the working directory is the helper's own
`os.getcwd()` (exact, no trailing-newline loss), folders are compared by `routing.route` (the importer's rule: only
`A-Z` is folded), every file and directory consulted passes `trustwalk.py`, and the probe cache is written through a
validated directory descriptor (exclusive creation, rename, no symlink followed) into a state directory that is not
a symlink, is yours and is not group/other-writable. The probe sends no key. When the helper is not on `PATH` (or
Python is missing, or it fails) the launch is treated as "cannot tell": a notice and an unchanged launch, or a
refusal under block; the shell never falls back to logic of its own. **This is a behaviour reduction compared with
shell-only hooks:** every omp start now needs a working Python 3.10+ and costs about 50 ms (about 26 ms of that the bare
interpreter; the helper imports only the standard library and two small modules, and loads the HTTP client only when
the probe cache has expired).

If the proxy is down, or the configuration cannot be trusted, the launch runs omp **unchanged**, which does **not**
enforce where its memory goes (an inherited `PI_CONFIG_FILES`, global settings or a repository's own config still
apply, so a repository naming another Hindsight server can still receive transcripts);
`OMP_HINDSIGHT_GUARD_ON_DOWN=block` refuses to start instead. In block mode "I do not know" is not permission
either: a missing, unreadable or entry-less routing table, any malformed entry (the folder of a broken entry would
look like outside every bank), an overlay that names no `apiUrl`, a bank without an overlay and a folder two banks
match equally well are all refused (exit 75). Only a fully parsed table that places the folder outside every bank
launches unchanged. The tests run the helper through zsh, bash 5, bash 3.2 (macOS), fish and the PATH shim.

### 3.6 Backup and outbox scripts (`scripts/`, `tests/test_scripts.py`)

- `backup.sh` works only in a directory that is new, empty or holds just its own files, that is yours and that is
  not a symlink, and whose whole ancestry passes `trustwalk.py` (checked before anything is created and again after,
  ACLs included); it takes an exclusive kernel lock (`flock`, through `lockrun.py`) on `.backup.lock`, so two runs
  cannot overlap and a crashed run leaves nothing stale (the lock file is never deleted or inferred from a pid).
- Dumps and exports are written under temporary names, validated (the table of contents for dumps; Python's
  `zipfile` reading every member and its checksum for exports, with no dependence on `unzip`) and only then renamed.
  Retention counts must be integers from 1 to 9999: larger values would wrap in the shell's arithmetic and delete
  everything. Export pruning matches the exact `export-<bank>-<date>-<six digit time>.zip` name, so a bank named
  `a-2026-11-09-123456` never shares a retention budget with bank `a`.
- A run with no banks to export fails (after making the dump) unless `HINDSIGHT_NO_EXPORT=1`, so a missing
  configuration cannot look like a healthy backup.
- `outbox-check.sh` refuses a symlinked outbox or any symlink inside it, treats 72 hours as stale (a warning), and
  keeps its once-a-day notice in a state directory it only trusts when it is yours, not a symlink and not
  group/other-writable. It reads and redacts local memories in memory through the importer to count unsynced ones.

## 4. Residual risks you accept by using it

1. **Redaction is incomplete** (SECURITY.md). Anything that gets through is stored and recalled.
2. **A holder of a bank key has that bank.** It can read everything in it (reads are not redacted), write to it
   (writes are), create and refresh mental models, and run `reflect`, which makes the server call its language
   model. The proxy has no rate limit and no per-key quota; a valid key can make many requests. The server uses a
   thread per connection with a 30 s socket timeout and a 300 s upstream timeout.
3. **Reads are unredacted.** Whatever was stored before the proxy existed, or that the model derived, is returned
   as stored.
4. **`/health/ready` needs no key** and answers with the upstream's status, so anyone who can reach the proxy can
   tell whether Hindsight is up. It reveals nothing else. It is the one path an unauthenticated client can use to
   make the proxy talk to Hindsight, so it has its own 5 s timeout, a 4 KiB reply limit and a 1 s shared cache.
   More generally, **unauthenticated clients, not only key holders, can consume connections**: the proxy answers
   `503` beyond 128 simultaneous connections, buffers at most 64 MiB of an upstream reply, and rejects short or
   ambiguous request framing (exact `Content-Length`, no `Transfer-Encoding` at all) **on every request, health
   checks included** (a body on a health check is refused and the connection closed), but it has no rate limit and
   socket timeouts are inactivity limits, not total deadlines.
5. **Loopback traffic is cleartext.** Another process that can read local network traffic (root, or a debugger
   attached as your user) sees keys and bodies. Remote access must be TLS-terminated by you.
6. **The route list is a snapshot.** A new omp or Hindsight feature that needs another route is refused until the
   code is changed. That is deliberate, but it breaks features silently from the user's side (a `404` in the proxy
   log). The upgrade checklist is in [`server-setup.md`](server-setup.md).
7. **Files holding memories in clear text.** Dumps and exports (`backup`), the importer's redacted export, and
   Hindsight's database contain memory text. They are created 0600 in 0700 directories; their protection beyond that
   is yours.
8. **Per-repo symlink mode** puts a link to a key-bearing file inside a repository. It is excluded from git
   locally (`.git/info/exclude`), but an editor, a backup tool or `git add -f` can still pick it up.
9. **A repository's own `.omp/config.yml` is trusted by omp.** With the hook, the overlay's URL, token and bank won
   over a conflicting project config in the one observation made (omp 18.18.0, print mode, macOS); that is not a
   documented guarantee. If you export a Hindsight token yourself, also export `HINDSIGHT_API_URL` and
   `HINDSIGHT_BANK_ID`.
10. **Dependencies.** The only third-party runtime dependency is PyYAML (reading overlays). The tool imports
    nothing at run time that it does not declare.

## 5. Out of scope

These attacker capabilities are **not** defended against, and every claim in this document is made on top of that
boundary:

- **A process running as your user.** It can read your key files and overlays, change `banks.json`, replace the
  hook files, edit your shell startup files and read the proxy's memory. The path checks cannot help: they only decide
  whether *someone else* could have changed a path.
- **Root.** The same, plus everything a path check trusts (root-owned directories and symlinks are trusted on purpose,
  because `/var`, `/tmp` and `/etc` are root-owned symlinks on common systems).
- **Anyone who can already write inside a directory the checks trust**: a directory that is yours, or root's, with
  no write access for group, other or an ACL. That is the definition of trusted, so the checks do not look further.
  An administrator who adds an ACL *after* a check, or who changes a directory's mode between the check and the use,
  is in this category (the check and the use are separate steps; with every directory above the path owned by you or
  root and closed to everyone else, nobody outside this category can change them in between).
- **Hardware, kernel and filesystem bugs; backups of your home directory; other machines that mount it.**
- Prompt injection through recalled memory, and what the language model does with it.
- The security of omp, Hindsight, Postgres and the language-model provider themselves, including what Hindsight's
  model provider sees of your (redacted) memories during extraction.
- Platforms other than macOS and Linux (no Windows; ACLs are inspected only where described above).
- If any of the above matters to you, run Hindsight and its database as a different operating-system user and keep
  bank keys in a secret store your tools read at launch.

## 6. Key rotation

Rotating a bank key: write a new key file, restart the proxy, run `overlays`, restart nothing else (hooks read the
overlay at each launch; sessions already running keep the old key until they end). Rotating the upstream key: change
it in Hindsight's configuration and in `keys/upstream.key` together, then restart both. `doctor` confirms the result.

## 7. Where an independent reviewer should look first

1. `proxy.py`: `parse_target`, `_segment`, `match_route`, `_prepare` (can any input reach `_forward` with a path
   that is not under the key's bank or not in `ROUTES`; can a header, query or body field smuggle an unredacted
   string; what happens on partial reads and keep-alive reuse after an error).
2. `redact.py`: backtracking and quadratic behaviour in every pattern; whether `redact_json` can skip a string
   position (dict keys are skipped by design); the identifier alphabet; idempotence.
3. `config.py` and `overlays.py`: key file checks (TOCTOU between check and read), atomic writes, URL rules.
4. `importer.py`: the digest covers exactly what is sent; ledger refusals; redirect handling; link allow-list matching.
5. `hooks/*` and `shellhooks.py`: quoting of paths with spaces and metacharacters, the rc-file editing, symlink
   behaviour, the probe and its cache files.
6. `scripts/*.sh`: variable handling under `set -u`, glob use in `prune`, file modes of dumps and exports.

## Guarantees, stated precisely

- **Destination history only grows.** A retry with fewer source rows than the failed attempt before it never narrows
  the record; confirming a document ties every one of its source rows to its bank.
- **Health checks are refused from the headers alone**; routed requests are authenticated before their body is read.
- **Document ids.** The importer builds an id from the identity (`mnemopi`, bank, label, table, row id) and keeps the
  readable form `ns:bank:label:table:id` only when it consists solely of `A-Za-z0-9:_.-@`, has no `..`, is at most
  120 characters, contains no colon inside the label or the row id (the one ambiguity of that form) and does not end
  like a hashed id. Otherwise the id is a readable prefix plus `@h` and the **full SHA-256** of the JSON of the exact
  parts. Two different identities therefore get different ids except through a SHA-256 collision, and a readable id
  can never equal a hashed one. The same rule gives source keys in the ledger (`label:w:id`, or `@` plus the
  SHA-256 when a colon is involved). Row ids are unique only within one mnemopi store, so a ledger records which
  root it belongs to and refuses another. The proxy refuses, when written, a `document_id` with any other
  character, with `..`, or that the token rules would rewrite (a document id is **refused**, where other identifier
  positions are rewritten): the stored id is the recorded one, and every id the importer writes can be read back
  through the proxy. The read-back accepts a reply up to 16 MiB and reports a longer one as `too-large`.
- **Folding.** Roots and working directories are compared with exactly `A-Z` folded to lower case, by one
  implementation (`routing.route`), used by the importer and by the hook helper alike. A filesystem that itself folds
  names (the default macOS one maps `ß` to `ss`) has no distinct sibling to confuse. Roots are written in ASCII with no
  `.`/`..` components.
- **Routing rows** have exactly one tab between two non-empty fields, no control character and valid UTF-8; a table
  that cannot be read completely is unknown configuration.
- **Paths.** Every configuration, key, overlay, routing-table, state and backup path is walked lexically with lstat
  (symlink targets read exactly, `..` followed like the kernel), with ACLs inspected, before it is used. What this
  guarantees: nobody outside the out-of-scope list in section 5 can redirect or alter such a path. Python and the
  helper can use a directory descriptor for the cache; the shell scripts use pathnames, which the ancestry rule
  makes safe against anyone who is not you or root.
- **Backups.** A failed or invalid export prunes nothing. The first backup date is recorded once in `.first-run` so the
  deadline for a bank's first export does not move when retention prunes old dumps.
