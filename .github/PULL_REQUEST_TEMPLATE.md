## What changed and why

<!-- One logical change per pull request. Link the issue if there is one. -->

## How you tested it

<!-- Commands you ran, the operating system and the Python version. -->

## Checklist

- [ ] One logical change, with tests (a bug fix has a test that fails without the fix)
- [ ] `ruff check .`, `ruff format --check .` and `pytest` pass
- [ ] `CHANGELOG.md` is updated, and the README or `docs/` if behaviour, configuration or the threat model changed
- [ ] New files are listed in `tools/public-tree-check/allowlist.txt`
- [ ] Test fixtures that look like secrets are built at run time, never written literally
- [ ] No real keys, personal paths, host names or addresses in the change
