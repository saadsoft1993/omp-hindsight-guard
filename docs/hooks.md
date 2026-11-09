# Choosing a bank by folder

omp has to be told which Hindsight bank (and which key) to use. This tool offers three ways. All are opt-in, and
you should use **one** of them.

| | Shell function (zsh, bash, fish) | PATH shim | Per-repo symlink |
|---|---|---|---|
| Works for | shells that load it | any shell, `bash -c`, multiplexer panes | omp started in that exact folder |
| Subfolders | yes (longest root wins) | yes | **no** (only the folder holding the link) |
| When the proxy is down | omp runs unchanged (destination not enforced), or refuses with `ON_DOWN=block` | the same | **no** probe: omp uses the link regardless, recall shows warnings |
| Child `omp` processes started by a session | get omp's global config | get their own folder's bank (they run the shim again) | follow their own cwd |
| Needs | `omp-hindsight-guard-pick` on `PATH`; the file sourced at startup | the same; one `PATH` line | one link per repo |

## What the function and the shim do

Both are thin: they call `omp-hindsight-guard-pick`, which reads `routes.tsv` (written by `omp-hindsight-guard
overlays`; exactly one tab per row, anything else is a malformed entry), finds the longest root containing the current
directory (symlinks resolved; `A-Z` folded to lower case and nothing else, the same code the importer uses), refuses
any file or directory someone else could replace (symlinks, ACLs), and then:

- a valid routing table that places the folder **outside every bank**: run omp **unchanged**, including whatever
  `PI_CONFIG_FILES` you had set. With no routes file at all (or one with no usable entry) omp also runs unchanged
  and silently, **unless** `OMP_HINDSIGHT_GUARD_ON_DOWN=block` is set: then "I cannot tell" is a refusal too (exit 75),
  as is a bank whose overlay is missing or names no `apiUrl`. (When a bank matches but its overlay is missing, one
  line on stderr says so);
- otherwise, **probe** the overlay's `apiUrl` with `GET <apiUrl>/health/ready` (no key, at most 1.5 s). If it does
  not answer `200`, run omp **unchanged** and print one line to stderr (`omp: shared memory (<bank>) unreachable;
  running with omp's existing configuration (its memory destination is not enforced; ...)`). "Unchanged" means
  exactly that: an inherited `PI_CONFIG_FILES`, your global settings and a repository's own config all still apply,
  so a repository that names another Hindsight server can still receive transcripts. With
  `OMP_HINDSIGHT_GUARD_ON_DOWN=block` the launch is refused instead, with exit status 75 and nothing started.
  The answer is cached per URL in the state directory for 30 s when up and 10 s when down. The cache is only used
  and written when that directory is yours, is not a symlink and is not writable by group or other (files are
  created exclusively and renamed into place through the directory's descriptor); otherwise every launch probes afresh;
- a folder that two banks match **equally well** (for example two spellings of one directory) selects neither bank
  and is treated the same way (notice, or refusal with `block`); the choice is never made by file order;
- otherwise run `omp --config <overlay> ...` with `PI_CONFIG_FILES` removed from omp's environment (only in this
  case), so the key is passed as a file path and is never exported. `omp config ...` ignores `--config`, so for that
  subcommand only, `PI_CONFIG_FILES=<overlay>` is set instead.

A session keeps the backend it chose at launch; it does not switch when the proxy goes down or comes back. A launch
that bypasses the function (a shell that did not load it, an IDE, a script using another shell) gets omp's own
configuration. Memories written locally during an outage reach the banks by re-running the import.

Settings (environment): `OMP_HINDSIGHT_GUARD_CONFIG_DIR`, `OMP_HINDSIGHT_GUARD_OVERLAY_DIR`, `OMP_HINDSIGHT_GUARD_ROUTES`,
`OMP_HINDSIGHT_GUARD_STATE_DIR`, `OMP_HINDSIGHT_GUARD_QUIET=1` (no notice), `OMP_HINDSIGHT_GUARD_ON_DOWN=block` (refuse to start instead, exit 75), `OMP_HINDSIGHT_GUARD_PROBE_TIMEOUT`,
`OMP_HINDSIGHT_GUARD_PROBE_UP_TTL`, `OMP_HINDSIGHT_GUARD_PROBE_DOWN_TTL`, and, for the shim only,
`OMP_HINDSIGHT_GUARD_REAL_OMP` (otherwise the shim finds the next `omp` on `PATH`).

## Installing

```sh
omp-hindsight-guard hook zsh            # copies the hook into the config dir and prints the line to add
omp-hindsight-guard hook zsh --install  # shows it, asks, then appends a marked block to ~/.zshrc (idempotent)
omp-hindsight-guard hook zsh --uninstall
```

`bash` (default file `~/.bashrc`), `fish` (default `~/.config/fish/config.fish`) and `shim` work the same way. The
shim needs `--rc FILE` for `--install` and `--uninstall` because the right file depends on your shell. `--rc` lets
you choose another file, for example `~/.zshenv` to cover non-interactive zsh too (omp started from a script,
`zsh -c`, a multiplexer pane that runs a command). Nothing edits a startup file without `--install`, and without
`--yes` it asks first. The block is delimited by `# >>> omp-hindsight-guard >>>` and `# <<< omp-hindsight-guard <<<`,
and `--uninstall` removes exactly that block.

Do not combine the function and the shim: the function would call the shim, and omp would receive `--config`
twice.

macOS notes: its `bash` is 3.2 and `/usr/bin/python3` is 3.9; the hooks work on 3.2, Homebrew's Python is needed for
the tool itself. Login shells read `~/.bash_profile`, not `~/.bashrc`; pass `--rc ~/.bash_profile` if that is the
file your terminal loads.

## Per-repo symlink mode

For people who do not want any shell hook:

```sh
omp-hindsight-guard link ~/code/home/app            # bank chosen from the roots; or: --bank home
omp-hindsight-guard link ~/code/home/app --remove
```

It links `<repo>/.omp/config.yml` to the bank's overlay and adds `/.omp/config.yml` to the repo's
`.git/info/exclude` (the overlay holds the key, so it must never be committed). It never replaces an existing
project config. What to know, observed with omp 18.18.0:

- **A project config applies only in the exact folder omp is started in.** A session started in a subfolder of the
  repo silently gets omp's global config. This is the main reason the hook is the recommended way.
- omp does **not** expand `${VAR}` or `file:` references in this config; the overlay holds the literal key.
- **omp trusts a repository's own `.omp/config.yml`** without asking. A cloned repo can switch Hindsight on and name
  a server. If you also export a Hindsight token in your shell (`HINDSIGHT_API_TOKEN`), that token would be sent to
  whatever server such a repo names. If you export one, also export `HINDSIGHT_API_URL` and `HINDSIGHT_BANK_ID`;
  environment variables override project settings. The hook avoids the problem by never exporting the key.
- There is no probe and no fallback: omp uses the linked overlay whether or not the proxy is up; recall shows
  warnings while it is down.
- `HINDSIGHT_*` variables alone do not turn Hindsight on: some config layer must set `memory.backend: hindsight`.

## What a hostile repository can and cannot do with the hook

Observed once, with omp 18.18.0 in print mode on macOS: with `--config <overlay>`, the overlay's `apiUrl`,
`apiToken` and `bankId` won over a project `.omp/config.yml` that named a different server, token and bank, and the
other server received no request. Not verified: the interactive TUI, other omp versions, and settings that the
overlay does not set (those still come from the project config as usual). Treat this as a useful property that you
re-check after upgrading omp, not as a guarantee.
