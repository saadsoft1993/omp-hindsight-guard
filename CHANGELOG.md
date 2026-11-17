# Changelog

All notable changes are recorded here. The project follows semantic versioning; while it is `0.x`, minor versions
may change configuration or behaviour, and the change is listed here.

## Unreleased

- `overlays`: generated overlays use `recallTimeoutMs: 8000`, `requestTimeoutMs: 15000` and `retainTimeoutMs: 15000`,
  which suit a server reached over the network.

## 0.1.1 - 2026-11-12

- `doctor`: on a machine where nothing listens at the default proxy address (`127.0.0.1:8888`, connection refused) and
  no `--proxy-url` was given, it now prints `no proxy answered at <url>; pass --proxy-url or set it in banks.json` as a
  warning instead of a failure, and says the isolation checks were not run. A proxy that answers badly, or a refused
  address given with `--proxy-url` or set in `banks.json`, still fails.

## 0.1.0 - 2026-11-11

First version of the toolkit.

- Redacting proxy in front of a self-run Hindsight server: route, method and query allow-lists, strict request
  target parsing, one key per bank compared in constant time, fail-closed errors, redaction of every write body,
  1,000,000-character string cap and 32 MiB body cap. Any number of banks.
- `banks.json`: one JSON configuration with banks, key files and folder roots; schema validation with
  unknown-field rejection; key files must be 0600 and distinct.
- `overlays`: per-bank omp settings overlays and the folder table, generated from `banks.json`; the URL is an
  argument; files 0600 in a 0700 directory.
- Folder-based bank selection: zsh, bash and fish functions, a PATH shim, and a per-repo symlink mode; all opt-in;
  run omp unchanged (with a notice, or refuse to start with `OMP_HINDSIGHT_GUARD_ON_DOWN=block`) when the proxy is down (cached health probe).
- `doctor`: configuration, key files, overlays, route table, and live per-bank key isolation (own bank `200`,
  other banks `404`, no key `401`).
- `import`: one-time mnemopi importer with dry run, confirmation digest, ledger, residual scan, label exclusions
  and a configurable allow-list of public share-link prefixes.
- `backup`, `outbox-check`, `canary-count`, `hsadmin`: parameterised shell scripts for macOS and Linux.
- Documentation: README, hooks, `banks.json` reference, server setup notes, threat model, security policy.

### Changes from the independent review (still 0.1.0)

- Redactor: spaced unquoted `name = value` lines (`~/.aws/credentials`, `.pypirc`, `.my.cnf`, TOML, INI) and `.npmrc`
  `_authToken=` lines are redacted and flagged by the residual scan; a secret-named JSON key with a list or object
  value is redacted leaf by leaf; URL parameter names are matched by meaning (`X-Amz-Signature`,
  `X-Amz-Security-Token`, `refresh_token`, `id_token`, any case); token-only fields (`types`, `timestamp`,
  `entities[*].type`, `trigger.mode`, ...) must look like identifiers. The remaining gaps are listed in SECURITY.md.
- Proxy: `Content-Length` must be plain digits and appear once; any upstream protocol error or out-of-range status
  is a `502`.
- Hooks: `PI_CONFIG_FILES` is removed only when an overlay is applied, otherwise omp runs unchanged; a matching
  bank with no overlay says so on stderr. `hook --uninstall` refuses (and changes nothing) when the end marker is
  missing, and writes through a symlinked startup file. `link` refuses a repo whose `.omp` is a symlink.
- `doctor --proxy-url` applies the overlay URL rule and never sends Hindsight's own key to a remote proxy;
  `--backup-dir` also checks each bank's newest export. Overlay URLs are validated and written as quoted YAML.
- Scripts: export pruning matches exactly one bank (`a` vs `a-b`); `HINDSIGHT_ADMIN` may be any executable; a large
  `pg_restore -l` no longer discards a good dump; `HINDSIGHT_BACKUP_DIR` must be empty or hold only backup files;
  the outbox check treats any group or other permission bit as a failure and escapes AppleScript text.
- Importer: `importance` is redacted and scanned; `--send` refuses an overlay whose `bankId` is another bank; a
  working directory containing a NUL byte routes to nothing.
- Repository: the test and publication-check steps are written out in CONTRIBUTING.md; a CI workflow (pinned actions, read-only permissions, gitleaks download checksum verified) is prepared but not enabled yet.

### Changes from the second independent review (still 0.1.0)

- Hooks: the notice no longer promises "local memory"; it says omp runs with its existing configuration and that its
  memory destination is not enforced. `OMP_HINDSIGHT_GUARD_ON_DOWN=block` refuses to start (exit 75) when the proxy
  is down, an overlay is missing, or two banks match a folder equally well; in the permissive mode two equal matches
  select no bank.
- Configuration integrity is enforced when files are opened: `banks.json`, key files and their directories must be
  yours and not writable by group or other; existing unsafe configuration, overlay and state directories are
  rejected. Roots are validated in the same canonical form routing uses (`/usr/..` and `~/x/..` are too broad; two
  spellings of one directory cannot belong to two banks).
- Importer: the ledger is locked for the whole `--send`/`--reconcile`; destinations are reserved before sending and
  stay reserved after a timeout; rows count as synced only after their operation completes (`--reconcile`,
  `--drop-unknown`); overwritten documents no longer leave stale content mappings; content already in another bank
  is listed (`content-also-in:`); URL, token and bank id come from one validated overlay read.
- Overlays: bank ids are written as quoted strings (`null`, `true`, `123` stay strings); API URLs may not carry
  credentials, queries, fragments or bad ports; existing symlinked overlay directories and files that are not
  this tool's are refused.
- Redactor: brackets in quoted or JSON-valued passwords no longer exempt them; identifiers carrying a
  `password: ...` assignment are refused.
- Proxy: exact request framing (short bodies and any `Transfer-Encoding` refused); the health probe has its own
  timeout, reply limit and shared cache; connections and buffered upstream replies are bounded.
- Scripts: backups take a lock, write under temporary names, validate dumps and archives before renaming, validate
  retention counts, and refuse symlinked or foreign directories; the outbox check refuses symlinks and uses an exact
  72-hour age; script commands fail on an invalid configuration instead of ignoring it.

### Changes from the third independent review (still 0.1.0)

- Importer: a destination leaves the ledger only on a refusal the server makes before storing anything (HTTP 4xx);
  5xx, 408, redirects, timeouts and crashes keep it. A document that is still unresolved is never sent again. A failed
  or cancelled operation leaves a `failed` record (retry to the same bank only). A reply without a usable operation id
  is never taken as synced; a pruned operation (`not_found`) or a missing id is settled by reading the document back.
  Operation statuses follow Hindsight 1.2.0 exactly (`pending`, `processing`, `completed`, `failed`, `cancelled`,
  `not_found`). `--drop-unknown` now releases unconfirmed documents and failed records (never an open operation).
  Cross-bank text is one consistent, documented policy, reported across the ledger and the current run. Rows whose
  working folder is gone need review and are not routing evidence.
- Backups: a kernel `flock` replaces the lock directory; exact export pruning; retention counts limited to 1-9999;
  exports validated with Python's `zipfile`; a run with no banks fails unless `HINDSIGHT_NO_EXPORT=1`. Needs python3.
- Hooks: in block mode a missing or empty routing table and an overlay without an `apiUrl` refuse the launch; state
  files are written only into a trusted state directory, through unpredictable temporary names. Roots in banks.json
  must be ASCII with no `.`/`..` components so every launcher agrees with Python.
- Proxy: health checks go through the same framing validation as every other request.
- Redactor: identifiers carrying `name:value` assignments in any spacing are refused; a snake_case or dotted value with
  a digit is a password in a quoted or JSON context.
- Startup files: unmatched, nested or stray markers make install and uninstall refuse and change nothing; `link
  --remove` refuses a symlinked `.omp`.
- Doctor: no longer claims an upstream-key check it skipped; a bank with no export fails once a week of backups exists.
- Publication tool: diagnostics hide private path and ref names.

### Changes from the second verification pass (still 0.1.0)

- Importer: a retry never narrows the destination history of a failed document; document read-back accepts replies up
  to 16 MiB and reports larger ones as `too-large`; generated and written document ids are limited to characters the
  proxy can read back; `--drop-unknown` help states its full scope.
- Proxy: health requests are refused from the headers alone, before any body is read.
- Hooks: in block mode any malformed routing-table entry refuses the launch; a failed permission probe disables the
  state cache.
- Config: every ancestor of a private directory is checked.
- Backups: a failed export prunes nothing; the first backup date is recorded once for the doctor's export deadline.

### Changes from the third verification pass (still 0.1.0)

- Path trust: configuration, overlays, routing tables and state directories are walked lexically with lstat (Python and
  all four launchers, plus `outbox-check.sh`), so the directory holding an intermediate symlink is checked; untrusted
  paths are treated as unknown configuration.
- Routing: one folding rule (`A-Z` only) in Python and every launcher; a routing row with an extra column or a control
  character is malformed.
- Document ids: injective (a hash suffix whenever the source identity needs a change), no `..`, and a written id that
  the token rules would rewrite is refused.
- Importer: HTTP 501 keeps the reservation (the proxy forwards the server's own).

### Changes from the fourth verification pass (still 0.1.0)

- Hooks: the four launchers are thin and call `omp-hindsight-guard-pick` (new console script). Routing, strict table
  parsing, the exact working directory, ASCII-only folding, path trust and the probe cache now live in one Python
  implementation (`hookpick.py`); the embedded shell walks, `curl` and locale-dependent shell classes are gone.
- Path trust (`trustwalk.py`): ACLs are inspected (macOS `ls -le`, Linux POSIX ACL attribute); symlink targets are read
  exactly; relative targets with `..` are resolved like the kernel does; backup and outbox scripts use it too.
- Importer: source identity is serialised unambiguously (hashed id and key when a colon is involved), the id suffix is
  the full SHA-256, and a ledger is bound to one mnemopi root.
- Documents: the out-of-scope attacker capabilities and the precise guarantees are written down in the threat model.

### Changes after a test on a second machine (still 0.1.0)

- Doctor: Hindsight 1.2.0 creates a bank on its first write, so right after `init` the own-bank listing answers 404. That is now a
  warning ("not created yet"; the other isolation checks still run and still fail on a real problem), not a failure; run `doctor`
  again after the first retain.
- Documents: the importer's operation statuses, the retain reply fields and the document read-back after a `not_found` operation
  were checked against a live Hindsight 1.2.0 server (macOS, scratch banks).
