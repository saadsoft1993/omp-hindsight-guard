# Running Hindsight for this tool (notes, not a managed install)

omp-hindsight-guard does not install, start or supervise Hindsight. These notes record what a self-run server
needs so that the proxy, the backups and the doctor work. They are a starting point, not a substitute for
[Hindsight's own documentation](https://hindsight.vectorize.io/); where the two disagree, Hindsight's wins.

What was checked, and what was not: the author ran this on **macOS (Apple silicon) with Hindsight 1.2.0**,
Homebrew PostgreSQL 17 and pgvector, and checked the environment variable names below against that release; the proxy,
the importer's operation and document read-back handling and the isolation checks were also run against a live 1.2.0
server on a second macOS machine, in scratch banks. The
Linux commands are ordinary Postgres and service-manager usage and have **not** been run by the author's test
suite. Version numbers are examples; pin whatever you have tested.

## 1. The shape of the setup

```
omp  ──(Bearer <bank key>)──>  omp-hindsight-guard proxy  ──(Bearer <upstream key>)──>  Hindsight  ──>  Postgres
                               127.0.0.1:8888, redacts writes       127.0.0.1:8890                 127.0.0.1:5432
```

- Hindsight listens on **loopback only** and requires an API key. Only the proxy knows that key (the file named
  by `proxy.upstream_key_file`). Nothing else, not even omp, talks to Hindsight directly.
- Clients (omp) talk to the proxy with a per-bank key. To reach the proxy from other machines, terminate TLS in
  front of it (a reverse proxy, `tailscale serve`, a VPN); do not publish the plain port.
- Postgres listens on loopback, uses password authentication (`scram-sha-256`), and its database belongs to a
  dedicated role.

## 2. PostgreSQL with pgvector

macOS (Homebrew), as an example:

```sh
brew install postgresql@17 pgvector
brew services start postgresql@17
# keg-only: the client tools are NOT on PATH. Use the full path or set HINDSIGHT_PG_BIN for this tool's scripts:
#   Apple silicon: /opt/homebrew/opt/postgresql@17/bin     Intel: /usr/local/opt/postgresql@17/bin
```

Debian and Ubuntu: `sudo apt install postgresql postgresql-contrib postgresql-NN-pgvector` (where `NN` is your
Postgres major version); the tools are on `PATH`.

Create the role and database, and **create the extensions as a superuser** (Hindsight's migrations skip some
silently if the role cannot):

```sql
CREATE ROLE hindsight LOGIN PASSWORD '<long random password>';
CREATE DATABASE hindsight OWNER hindsight;
\c hindsight
CREATE EXTENSION vector;
CREATE EXTENSION pg_trgm;
CREATE EXTENSION btree_gin;
```

Keep `listen_addresses = 'localhost'` and make every `pg_hba.conf` line `scram-sha-256` (Homebrew's fresh cluster
may use `trust`; check). Store the password in a `.pgpass` file (`chmod 600`) for the backup scripts:
`127.0.0.1:5432:hindsight:hindsight:<password>`.

## 3. Hindsight

```sh
uv tool install hindsight-api==1.2.0 --python 3.13     # entry points: hindsight-api, hindsight-admin, hindsight-worker
```

Hindsight reads a `.env` file from its **working directory**. A process started anywhere else does not find it and
silently uses an embedded development database with an empty bank. So: keep the file in one directory (the scripts
default to `~/.config/hindsight`, mode 0700, file 0600), start Hindsight with that directory as its working
directory, and use `omp-hindsight-guard hsadmin ...` for `hindsight-admin`, which does the same.

Variables the author set (names as of 1.2.0; the values in angle brackets are yours):

| Variable | Value | Why |
|---|---|---|
| `HINDSIGHT_API_DATABASE_URL` | `postgresql://hindsight:<password>@127.0.0.1:5432/hindsight` | the database above |
| `HINDSIGHT_API_HOST` / `HINDSIGHT_API_PORT` | `127.0.0.1` / `8890` | the default is all interfaces on 8888; this keeps it on loopback and leaves 8888 for the proxy |
| `HINDSIGHT_API_TENANT_EXTENSION` | `hindsight_api.extensions.builtin.tenant:ApiKeyTenantExtension` | turns on API-key authentication |
| `HINDSIGHT_API_TENANT_API_KEY` | the contents of `keys/upstream.key` | the key only the proxy knows |
| `HINDSIGHT_API_LLM_PROVIDER` / `_MODEL` | your choice | Hindsight needs a language model for extraction and consolidation; which one is your decision and your account |
| `HINDSIGHT_API_LLM_TRACE_ENABLED` | `false` | prompt traces would store request text, including anything that slipped past redaction |
| `HINDSIGHT_API_LLM_TRACE_DELETE_WITH_DOCUMENT` | `true` | second layer if traces are ever turned on |
| `HINDSIGHT_API_DB_POOL_MAX_SIZE` | `20` | optional |

Acceptance checks before you point omp at it:

- `curl http://127.0.0.1:8890/health/ready` answers `200`;
- a request without the key is refused (`401`);
- nothing listens on 8890 or 5432 on a non-loopback address (`lsof -nP -iTCP -sTCP:LISTEN` on macOS,
  `ss -ltnp` on Linux);
- `~/.hindsight/data` does not exist (it would mean something started the embedded database).

## 4. The proxy as a service

`omp-hindsight-guard proxy` runs in the foreground and logs one line per request (method, bank, route class,
status, number of redactions; never bodies, queries, ids or keys). Run it under your service manager. Examples,
**not run by the author's tests**:

systemd (user unit, `~/.config/systemd/user/omp-hindsight-guard.service`):

```ini
[Unit]
Description=omp-hindsight-guard proxy
After=network.target

[Service]
ExecStart=%h/.local/bin/omp-hindsight-guard proxy
Restart=on-failure
UMask=0077

[Install]
WantedBy=default.target
```

`systemctl --user enable --now omp-hindsight-guard` (and `loginctl enable-linger $USER` to keep it running without a
login). launchd (`~/Library/LaunchAgents/<your.label>.omp-hindsight-guard.plist`) with `ProgramArguments` set to the
full path of `omp-hindsight-guard` and `proxy`, `KeepAlive`, `RunAtLoad` and `Umask` 63 (decimal for 077). Give the
service the same `HOME` (or `OMP_HINDSIGHT_GUARD_CONFIG_DIR`) you use at the command line.

## 5. Backups

`omp-hindsight-guard backup` runs `pg_dump -Fc` without the `llm_requests` table data into a 0700 directory with
0600 files, verifies the dump lists a `documents` table (otherwise the old dumps are kept and it exits non-zero),
prunes to the newest N, and once a week (or with `HINDSIGHT_EXPORT=1`) runs `hindsight-admin export-bank` for
every bank in `banks.json`. A run with no banks to export fails (after making the dump) unless
`HINDSIGHT_NO_EXPORT=1`. Files are written under temporary names and renamed after they validate (an export must be
a zip that Python reads completely, checksums included). Only one backup runs at a time (a kernel lock, so a crashed
run leaves nothing to clean up; an empty `.backup.lock` file stays in the directory), the directory must not be a
symlink, must be yours and must hold nothing but backup files, and the retention counts must be integers from 1 to
9999. It needs `python3` (`HINDSIGHT_PYTHON`). Set `HINDSIGHT_PG_BIN`, `HINDSIGHT_CONF_DIR` and the others as
described at the top of the script. `omp-hindsight-guard doctor --backup-dir <dir>` fails when the newest dump is
older than 26 hours, when a bank's newest export is older than 8 days, and when a bank still has no export once
backups began (the date `backup.sh` recorded once in `.first-run`, else the oldest dump still there) more than 8 days
ago.

**Importer and Hindsight's operation retention.** The importer confirms an asynchronous retain by asking
`GET /v1/default/banks/<bank>/operations/<id>`. When Hindsight is run with `HINDSIGHT_API_OPERATION_RETENTION_DAYS`
above 0 (the default, 0, never prunes), finished operations disappear after that many days and read `not_found`; the
importer then reads the document itself (`GET .../documents/<id>`, which the proxy allows) and counts it imported only
if its content hash, or its stored text, matches what was sent. If the server stores no document text and sanitises
it, the hash can differ and the row is reported `unconfirmed` instead (never silently pending): check the server and
use `import --reconcile --drop-unknown` to forget it. Run `import --reconcile` within the retention window to avoid
the question altogether.

A restore needs the same three extensions created in the target database first, or `pg_restore` reports errors.
Practise a restore into a scratch database once.

## 6. Upgrade checklist (Hindsight, omp, this tool)

1. `omp-hindsight-guard backup` (and an export of each bank).
2. Upgrade (`uv tool install hindsight-api==<new> --python 3.13 --force`; reinstall this tool the way you
   installed it, with `--force`).
3. Restart; check `/health/ready`.
4. `omp-hindsight-guard doctor`. It must show every bank passing its isolation check.
5. Run the **redaction canary**: send fake credentials through the proxy (`omp-hindsight-guard redact` shows what the
   patterns catch; build the fakes at run time and never paste real ones), then
   `omp-hindsight-guard canary-count <fake>` must print `none` for every needle.
6. Use omp normally for a session and read the proxy log. A `404` on a route omp uses means the new version needs a
   route the proxy does not forward; that is the proxy failing closed, and adding the route is a code change to
   `ROUTES` in `proxy.py` with its tests, not a configuration option.
7. Re-check `docs/hooks.md` claims you rely on (omp precedence of `--config` over a project config).

## 7. Same-user limit

Anything running as your user can read `~/.config/hindsight`, the key files and the overlays, and therefore the
database password and every bank key. Password authentication stops other users and password-less connections, not
your own programs. If that is not acceptable, run Hindsight and its database as a separate operating-system user.
