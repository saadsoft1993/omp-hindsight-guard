# banks.json reference

The single configuration file. Default location: `~/.config/omp-hindsight-guard/banks.json` (or
`$XDG_CONFIG_HOME/omp-hindsight-guard/banks.json`; or the directory named by `OMP_HINDSIGHT_GUARD_CONFIG_DIR`; or
any file with `--config FILE`). It is refused unless it is a regular file owned by you, not writable by group or other, in a directory with the same properties (otherwise another user could point the proxy's upstream at their own listener and receive Hindsight's key). It contains **paths to key files, never
keys**. Unknown fields are rejected, so a typo cannot silently weaken a setting; duplicate fields are rejected.

```json
{
  "version": 1,
  "proxy": {
    "listen_host": "127.0.0.1",
    "listen_port": 8888,
    "upstream_url": "http://127.0.0.1:8890",
    "upstream_key_file": "keys/upstream.key",
    "allow_remote_listen": false
  },
  "banks": {
    "client-a": { "key_file": "keys/bank-client-a.key", "roots": ["~/code/client-a"] },
    "home":     { "key_file": "keys/bank-home.key",     "roots": ["~/code/home", "~/notes"] }
  },
  "import": {
    "mnemopi_root": null,
    "exclude_labels": [],
    "allow_link_prefixes": ["https://share.example.com/doc/"]
  }
}
```

Relative paths are relative to the directory that holds `banks.json`.

## `version`

Must be `1`.

## `proxy`

| Field | Default | Meaning |
|---|---|---|
| `upstream_key_file` | required | File holding Hindsight's own API key. The proxy sends this key upstream in place of the client's key. |
| `listen_host` | `127.0.0.1` | Address the proxy binds. `127.0.0.1`, `localhost` and `::1` are always allowed. Anything else needs `allow_remote_listen`. |
| `listen_port` | `8888` | Port the proxy binds (1-65535). |
| `upstream_url` | `http://127.0.0.1:8890` | Hindsight. Must be `http://` on `127.0.0.1`, `localhost` or `[::1]`: the upstream key is sent in clear text, so the proxy runs next to the server. |
| `allow_remote_listen` | `false` | Permit a non-loopback `listen_host`. Only do this behind a TLS terminator and a firewall you control. |

## `banks`

An object with at least one bank; the key is the bank name (which is also the Hindsight bank id). Any number of
banks.

- Bank names: 1-64 characters from letters, digits, `_` and `-`, starting with a letter or digit; names must differ
  ignoring case.
- `key_file` (required): a file holding this bank's proxy key. The key is what a client sends as
  `Authorization: Bearer <key>`; it only ever reaches this bank.
- `roots` (optional, default none): folders that belong to the bank. Each is `~/...` or an absolute path, plain
  ASCII, with no control characters (no tab or newline), no `.`, `..` or empty (`//`) components, and never `~` or
  `/` alone or anything that resolves to them through a symlink. The restriction exists because every launcher
  (zsh, bash, fish, the shim) resolves a root with its own shell: only a spelling they all reduce to the same
  directory as Python does is accepted (`..` through a folder that does not exist is resolved by Python but not by
  bash). Everything is compared with exactly `A-Z` folded to lower case, in Python and in every launcher. Folders *below* a root may have
  any name. The same root cannot belong to two banks (compared ignoring case, symlinks resolved). A bank with no
  roots can still be reached through `link --bank` and the importer.

## Key files

One key per file, 32 to 512 printable ASCII characters (no spaces, no `"`, no `\`), the file owned by you and
**not readable by group or other** (`chmod 600`). Every key, including the upstream key, must be different: a
shared key would let one bank read another. `omp-hindsight-guard init` creates compliant files; to make one by hand:

```sh
umask 077; mkdir -p ~/.config/omp-hindsight-guard/keys
python3 -c 'import secrets; print(secrets.token_urlsafe(48))' > ~/.config/omp-hindsight-guard/keys/bank-home.key
```

## `import`

| Field | Default | Meaning |
|---|---|---|
| `mnemopi_root` | `null` | Where omp's local `mnemopi` banks live (`null` = `~/.omp/agent/memories/mnemopi/banks`). |
| `exclude_labels` | `[]` | mnemopi labels (prefixes, ignoring case) the importer never sends. `--exclude-label` adds more. |
| `allow_link_prefixes` | `[]` | `https://` URL prefixes ending in `/`. The 8-128 character id right after such a prefix is treated as a public share id, not a secret, **in the import's residual scan only**. The proxy is unaffected. Exact prefix match: `https://share.example.com.evil.example/doc/...` is not allowed by `https://share.example.com/doc/`. |

## Files derived from it

`omp-hindsight-guard overlays` writes, into the overlay directory (0700, files 0600):

- `<bank>.yml`, one omp settings overlay per bank, containing that bank's key;
- `routes.tsv`, one `<bank><TAB><root>` line per root, which the shell hooks read.

Run it again after every change to `banks.json`; `doctor` reports an overlay or route table that is out of date.
