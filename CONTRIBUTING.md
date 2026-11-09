# Contributing to omp-hindsight-guard

Thanks for helping. This is a small toolkit (a redacting proxy, per-folder memory banks, an importer and a few operations
scripts) for people who run their own [Hindsight](https://hindsight.vectorize.io/) server with
[omp](https://github.com/can1357/oh-my-pi). It is maintained by one person, so small, focused changes with tests are the
easiest to review.

## Before you start

- **Bugs and ideas:** open an issue and pick the matching template. For a larger change (a new proxy route, a new kind of
  secret, a new shell, a change to how folders map to banks), please open an issue first and agree on the approach.
- **Security problems:** do not open an issue. Use the **Report a vulnerability** button on the repository's Security tab
  (private vulnerability reporting), as described in [`SECURITY.md`](SECURITY.md). That includes a way to read or write
  another bank, to forward a request the proxy should refuse, or to get a secret past the redactor in a shape it claims to
  handle.
- **Redaction is pattern matching.** A change that makes the redactor catch another real secret shape is welcome; a change
  that claims more than pattern matching can deliver is not. Keep [`SECURITY.md`](SECURITY.md) ("The limits of redaction")
  true.

## Set up

You need Python 3.10 or newer (macOS's built-in `/usr/bin/python3` is 3.9 and does not work), [`uv`](https://docs.astral.sh/uv/)
(or `venv` and `pip`), and [`shellcheck`](https://www.shellcheck.net/) if you touch the shell scripts. zsh, bash and fish
are optional: their tests are skipped when the shell is not installed.

```sh
git clone https://github.com/saadsoft1993/omp-hindsight-guard
cd omp-hindsight-guard
uv venv && uv pip install -e '.[test]' ruff
source .venv/bin/activate
```

## What to run

```sh
ruff check . && ruff format --check .
pytest                                  # hermetic: scratch HOME, random loopback ports, no network, no real shell files
tools/public-tree-check/selftest.sh     # the checker that guards what gets published
shellcheck -x src/omp_hindsight_guard/scripts/*.sh src/omp_hindsight_guard/hooks/*.bash src/omp_hindsight_guard/hooks/omp-shim.sh
```

To run the suite on Ubuntu with Python 3.10 and 3.14 and with bash, zsh and fish installed (the checks above plus the tests of every hook variant):

```sh
docker build -f tools/container-test/Dockerfile -t omp-hindsight-guard-test . && docker run --rm omp-hindsight-guard-test
```

Tests never use your real home, shell files, configuration or network, and build every secret-looking fixture at run
time so that secret scanners stay quiet. Please follow the same rule in new tests: never put a real-looking token in a
file.

There is no continuous-integration workflow in this repository yet, so nothing runs your checks for you: run the commands
above (and the container run when you touch a hook or a script) before you open a pull request, and say in the description
what you ran. The tree check also has to pass:

```sh
printf 'Saad bin Abid <saadsoft1993@gmail.com>\n' > /tmp/identities.txt
python tools/public-tree-check/public_tree_check.py . --no-history \
  --allowlist tools/public-tree-check/allowlist.txt \
  --exempt tools/public-tree-check/exemptions.json \
  --identities /tmp/identities.txt
```

It checks allowlisted paths, wording, and that no personal paths, host names or secrets are in the tree. If you add a file, the
allowlist in `tools/public-tree-check/allowlist.txt` has to list it; add the path to your pull request. The full release gate
(`tools/public-tree-check/release_gate.py`, which also requires every commit to carry the maintainer's identity) is
run by the maintainer before a release, not by contributors.

## Pull requests

- **One logical change per pull request.** A bug fix, a feature, or a refactor: not a mix.
- **Tests are required.** A bug fix comes with a test that fails without the fix. A new redaction rule comes with tests of
  what it catches and of look-alikes it must leave alone. A change to a proxy rule or a route comes with a test of what is
  refused as well as what is allowed.
- **Update `CHANGELOG.md`** under the next version, and the README or `docs/` when behaviour, configuration or the threat
  model changes.
- **Keep the commits plain:** an imperative subject line that says what changed, a body that says why when it is not obvious.
- **Style:** `ruff` decides (tabs, double quotes, line length 110); match the code around your change and do not reformat
  files you are not changing.
- **Dependencies:** the tool depends on PyYAML only. Adding a runtime dependency needs an issue first.
- Write the description with the pull request template; say how you tested the change and on which operating system and
  Python version.

## Licence

By contributing you agree that your contribution is licensed under the MIT licence of this repository (see
[`LICENSE`](LICENSE)).
