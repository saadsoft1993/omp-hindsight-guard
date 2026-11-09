# omp-hindsight-guard

A small toolkit for people who run their own [Hindsight](https://hindsight.vectorize.io/) memory server and use it
from [omp](https://github.com/can1357/oh-my-pi). It does four things:

1. **A redacting proxy** between omp and Hindsight. Every write is scanned for recognisable secrets before it is
   stored; each client key is tied to exactly one memory bank; only the routes omp needs are forwarded.
2. **Memory banks by folder.** Work in `~/code/client-a` writes to the `client-a` bank, work in `~/code/home`
   writes to `home`, anything else keeps omp's own configuration. Any number of banks, one key each.
3. **A one-time importer** that moves memories from omp's local `mnemopi` store into the banks, with a dry run, a
   confirmation digest, a ledger and a residual-secret scan.
4. **Backup and health scripts** for the Postgres database behind Hindsight, plus `doctor`, which checks that the
   banks really are isolated from each other.

It does **not** install, run or manage Hindsight itself. [`docs/server-setup.md`](docs/server-setup.md) describes
what a self-run server needs; you operate it.

> **Read [`SECURITY.md`](SECURITY.md) before relying on the redaction.** Pattern redaction catches secrets that
> have a recognisable shape. It does not catch a bare password in a sentence, a secret split across two fields, or
> one hidden with extra encoding. It lowers the chance of leaking a credential into memory; it is not a guarantee.

## Requirements

- Python 3.10 or newer (macOS's built-in `/usr/bin/python3` is 3.9 and is **not** supported; use Homebrew, `uv` or
  python.org). The test suite has been run on Python 3.10 and 3.14 on macOS (zsh, bash 5, bash 3.2 and the PATH shim;
  fish is skipped where it is not installed) and in an Ubuntu container (those shells plus fish). Nothing else has
  been tried: not Windows, not other Linux distributions, not other shell versions.
- `PyYAML` (declared as a dependency; commands that need it stop with a clear message if it is missing).
- A running Hindsight server reachable on loopback from the machine that runs the proxy.
- For the shell hooks: zsh, bash (3.2+) or fish (3.5+), or any shell with the PATH shim, and the helper `omp-hindsight-guard-pick`
  (installed with the tool; it must be on `PATH` where omp is launched). No `curl`.
  **The launchers now need Python 3.10+ at every omp start.** They used to be shell-only. They are thin now: the
  helper makes every decision (routing, trust checks, the health probe), because duplicating that logic in four shell
  dialects kept producing disagreements. It adds about 50 ms to a launch (measured on macOS, about 26 ms of it the bare
  interpreter; about 25 ms more when the probe cache has expired). If Python or the helper is unavailable, omp starts
  unchanged with a notice, or is refused with `OMP_HINDSIGHT_GUARD_ON_DOWN=block`; the shell never falls back to
  its own logic.
- For the backup scripts: `bash`, `python3` (the backup lock and archive check), and the Postgres client tools `pg_dump` and `pg_restore`.

## Install

```sh
uv tool install git+https://github.com/saadsoft1993/omp-hindsight-guard    # or: pipx install <same URL>
omp-hindsight-guard --version
```

From a clone: `uv tool install .` (or `pip install .` inside a virtual environment).

## Quick start

```sh
# 1. Describe your banks and which folders belong to which. Creates ~/.config/omp-hindsight-guard/ with
#    banks.json and one random key file per bank (0600, in a 0700 directory). Never overwrites.
omp-hindsight-guard init --bank 'client-a=~/code/client-a' --bank 'home=~/code/home' --bank 'home=~/notes'

# 2. Put the upstream key (keys/upstream.key) into your Hindsight server as its API key; see docs/server-setup.md.

# 3. Start the proxy (loopback only by default, 127.0.0.1:8888 -> Hindsight on 127.0.0.1:8890).
omp-hindsight-guard proxy        # run it under systemd, launchd, tmux... your choice

# 4. Write one omp settings overlay per bank, and the folder table the hooks read.
omp-hindsight-guard overlays

# 5. Check everything, including that each key can only reach its own bank.
omp-hindsight-guard doctor      # a bank shows a warning until its first write: Hindsight creates a bank on first use

# 6. Opt in to folder-based banks (pick ONE of the ways in docs/hooks.md), for example for zsh:
omp-hindsight-guard hook zsh --install        # shows the line and asks before appending it to ~/.zshrc
```

`omp-hindsight-guard route ~/code/home/app` prints the bank a folder belongs to (`-` and exit code 1 when none).

Nothing is on by default: with no `banks.json` there is no bank, no key and no listener, and a shell hook does
nothing until you source it.

## How folders map to banks

`banks.json` lists roots per bank (`~/...` or an absolute path). A directory belongs to the **longest matching
root**, after resolving symlinks and ignoring case. A directory outside every root gets no shared memory (omp's own
configuration applies). There is no default bank, on purpose: a stray session must not write into the wrong one.

The hook picks the bank's overlay (an omp settings file holding that bank's proxy key) and passes it to omp as
`--config <overlay>`. The key is never exported to the environment. If the proxy does not answer a short health
probe, the launch runs omp **unchanged and says so**: omp keeps whatever configuration it already has (an inherited
`PI_CONFIG_FILES`, your global settings, a repository's own `.omp/config.yml`), so where its memory goes is **not
enforced**. Set `OMP_HINDSIGHT_GUARD_ON_DOWN=block` to refuse to start instead (exit 75). Details, the PATH shim and
the per-repo symlink mode, with their limits, are in [`docs/hooks.md`](docs/hooks.md).

## Configuration

One JSON file, `banks.json` (schema in [`docs/banks-json.md`](docs/banks-json.md); example in
[`banks.example.json`](banks.example.json)). It holds paths to key files, never keys. Defaults:

| Thing | Default | Override |
|---|---|---|
| Configuration directory | `~/.config/omp-hindsight-guard` (or `$XDG_CONFIG_HOME/...`) | `OMP_HINDSIGHT_GUARD_CONFIG_DIR`, `--config FILE` |
| Overlays and `routes.tsv` | `<config dir>/overlays` (0700) | `OMP_HINDSIGHT_GUARD_OVERLAY_DIR`, `overlays --out` |
| State (reachability cache, import ledger, exports, backups) | `~/.local/state/omp-hindsight-guard` (or `$XDG_STATE_HOME/...`) | `OMP_HINDSIGHT_GUARD_STATE_DIR` |
| Proxy listens on | `127.0.0.1:8888` | `proxy.listen_host`, `proxy.listen_port` |
| Hindsight upstream | `http://127.0.0.1:8890` (loopback only) | `proxy.upstream_url` |

The proxy refuses to listen on anything but loopback unless `proxy.allow_remote_listen` is `true`. To reach it from
another machine, put a TLS terminator you control in front of it (a reverse proxy, `tailscale serve`, ...) and give
the overlays that HTTPS address: `omp-hindsight-guard overlays --url https://memory.example:8898`. The overlay
generator refuses a plain-`http` URL to anything that is not this machine, because the key travels in a header.

## Importing from omp's local memory

If you used omp's `mnemopi` memory before, move it once:

```sh
omp-hindsight-guard import                      # dry run: counts and routing only, never contents; prints a digest
omp-hindsight-guard import --send --confirm <digest>
```

Rows route to banks by the folder they were written in. Rows outside every root, rows that cannot be placed
unambiguously (`review`), superseded or expired rows and excluded labels are not sent. `--send` refuses when the
residual scan still finds something secret-looking, when the ledger shows a row already went to another bank, or
when the digest does not match what would be sent. Public share links whose id is not a secret can be allow-listed
with `import.allow_link_prefixes` in `banks.json`. See `omp-hindsight-guard import --help`.

The server answers writes asynchronously, so an accepted request is not yet a stored memory. The ledger records each
batch's destination **before** it is sent and counts a row as imported only once the server reports its operation
`completed`, or, when the operation is gone (the server prunes finished operations after
`HINDSIGHT_API_OPERATION_RETENTION_DAYS`) or the reply carried no operation id, once the document itself is read back
with the content that was sent (the document read-back accepts replies up to 16 MiB and document ids made only of
letters, digits and `: _ . - @`, which is all the importer generates and all the proxy will write). An operation the server
reports as `pending` or `processing` is simply still open (exit status 0, nothing to decide). Anything else that is not
confirmed or failed is printed as `unconfirmed` (exit status 1) and stays on record: a
document is never reported imported on a guess, and never sent a second time while it is unresolved
(`held_unresolved=`). Only a refusal the server makes before storing anything (HTTP 4xx) forgets a destination; a 5xx
or a lost connection keeps it, so those rows cannot go to another bank. After an interrupted send, run
`omp-hindsight-guard import --reconcile`; `--drop-unknown` additionally forgets the documents still unconfirmed and
the `failed` records, and is meant for after you have looked at the server yourself. Only one import runs at a time.
Memories whose text also appears in another bank are listed as `content-also-in:` lines (against the ledger and the
rest of the same run): that is a policy of this tool, not an isolation guarantee; read them before `--send`. Rows whose
working folder no longer exists are held for review (`--include-review`).

## Backups and health

```sh
omp-hindsight-guard backup          # pg_dump (+ weekly per-bank export), prunes old files; see the script header
omp-hindsight-guard outbox-check    # omp's undelivered-memory outbox, readable-by-others check, unsynced count
omp-hindsight-guard canary-count    # redaction canary: count rows containing a needle, per table
omp-hindsight-guard hsadmin ...     # hindsight-admin, always run from the directory with Hindsight's .env
omp-hindsight-guard doctor --backup-dir ~/.local/state/omp-hindsight-guard/backups
```

The scripts are parameterised by environment variables (documented at the top of each file), with no Homebrew or
Debian paths baked in. On macOS with Homebrew's versioned Postgres, set `HINDSIGHT_PG_BIN=/opt/homebrew/opt/postgresql@17/bin`
(Intel: `/usr/local/opt/postgresql@17/bin`); on Debian and Ubuntu the tools are on `PATH`. Schedule them with cron,
a systemd timer or launchd; the tool does not install schedules.

## Uninstall and purge

Uninstalling keeps your data; purging removes it. Do them in this order.

1. Remove the hook: `omp-hindsight-guard hook zsh --uninstall` (and `--rc FILE` for a file you chose; same for
   `bash`, `fish`, `shim`). Remove per-repo links with `omp-hindsight-guard link REPO --remove`.
2. Stop the proxy and any schedules (backup, outbox check) you created.
3. `uv tool uninstall omp-hindsight-guard` (or `pipx uninstall omp-hindsight-guard`).
4. **Purge** (optional, destroys keys and local state): delete the configuration directory (holds `banks.json`,
   the key files and the overlays, which contain keys), the state directory (import ledger, redacted exports,
   backups made by `backup`), and the hook copies under the configuration directory. If you keep using Hindsight,
   rotate its upstream key.
5. The memories themselves live in your Hindsight database. This tool never deletes them, and omp's `/memory
   clear` does not either. Delete a bank with Hindsight's own UI or API (the proxy does not forward deletes).

## Limits worth knowing

- The proxy forwards a fixed list of routes written for omp's use of Hindsight. After upgrading omp or
  Hindsight, run `doctor` and watch the proxy log for unexpected `404`s; a feature that needs another route is
  refused rather than passed through. The checklist is in [`docs/server-setup.md`](docs/server-setup.md).
- Same-user processes on the machine can read the key files and overlays. The proxy protects the server and the
  banks from each other; it does not protect secrets from other programs running as you.
- The threat model, including what an attacker who can run code as your user can still do, is in
  [`docs/threat-model.md`](docs/threat-model.md).

## Development

```sh
uv venv && uv pip install -e '.[test]' ruff && source .venv/bin/activate
ruff check . && ruff format --check .
pytest                       # hermetic: scratch HOME, random loopback ports, no network, no real shell files
tools/public-tree-check/selftest.sh
# the same suite on Ubuntu with Python 3.10 and 3.14, with bash, zsh and fish installed:
docker build -f tools/container-test/Dockerfile -t omp-hindsight-guard-test . && docker run --rm omp-hindsight-guard-test
```

The tests build every secret-looking fixture at run time so secret scanners stay quiet without an allow-list.
fish and zsh tests are skipped when the shell is not installed; the container installs both. How to contribute:
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Licence

MIT, see [`LICENSE`](LICENSE).
