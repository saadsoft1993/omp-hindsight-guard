"""Install the shell hooks (zsh, bash, fish function; PATH shim) and the per-repo symlink mode.

Nothing is installed by default and nothing edits a shell startup file unless asked with --install, which
shows the exact lines first and, without --yes, asks. The hook files are copied into the configuration
directory so a shell startup `source` line does not depend on where Python put the package.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from importlib import resources
from pathlib import Path
from typing import TextIO

from omp_hindsight_guard.config import Config, ConfigError, makedirs_private
from omp_hindsight_guard.routing import bank_for_path

SHELLS = ("zsh", "bash", "fish", "shim")
HOOK_NAMES = {
	"zsh": "omp-hindsight-guard.zsh",
	"bash": "omp-hindsight-guard.bash",
	"fish": "omp-hindsight-guard.fish",
	"shim": "omp-shim.sh",
}
DEFAULT_RC = {"zsh": "~/.zshrc", "bash": "~/.bashrc", "fish": "~/.config/fish/config.fish"}
BEGIN = "# >>> omp-hindsight-guard >>>"
END = "# <<< omp-hindsight-guard <<<"
EXCLUDE_LINE = "/.omp/config.yml"

LINK_NOTES = """\
Per-repo mode, what to know:
- omp applies a project config only in the exact folder it is started in, not in subfolders. A session started
  in a subfolder gets omp's own configuration (no bank).
- The link holds the bank's proxy key (it points at a 0600 overlay). Never commit it: this tool adds
  /.omp/config.yml to the repo's .git/info/exclude when it can.
- omp does not expand ${VAR} or file: references in this config, and a repo's own .omp/config.yml is trusted
  by omp. If you export a Hindsight token in your shell, also export HINDSIGHT_API_URL and HINDSIGHT_BANK_ID so a
  cloned repo cannot point that token at a server of its choosing.
- There is no health probe and no fallback here (the shell hooks run omp unchanged, with a notice, when the proxy
  is down); recall shows warnings.
- A repo that already has its own .omp/config.yml is left alone."""


def hook_text(shell: str) -> str:
	return (resources.files("omp_hindsight_guard") / "hooks" / HOOK_NAMES[shell]).read_text(encoding="utf-8")


def _escape(text: str, syntax: str) -> str:
	"""Escape for a double-quoted string: `\\`, `"` and `$` in both syntaxes; the backtick only in POSIX shells
	(fish keeps a backslash before it)."""
	text = text.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")
	return text if syntax == "fish" else text.replace("`", "\\`")


def shell_quote_path(path: Path, home: Path | None = None, syntax: str = "posix") -> str:
	"""A double-quoted path for a startup file, `$HOME`-relative when the file lives under HOME."""
	home = home or Path.home()
	try:
		rel = path.relative_to(home)
	except ValueError:
		return '"' + _escape(str(path), syntax) + '"'
	return '"$HOME/' + _escape(str(rel), syntax) + '"'


def write_hook(shell: str, config_dir: Path) -> Path:
	"""Copy the hook (or shim) into the configuration directory; returns where it is."""
	if shell == "shim":
		target = config_dir / "shim" / "omp"
	else:
		target = config_dir / "hooks" / HOOK_NAMES[shell]
	makedirs_private(target.parent)
	target.write_text(hook_text(shell), encoding="utf-8")
	target.chmod(0o755 if shell == "shim" else 0o644)
	return target


def startup_line(shell: str, installed: Path, syntax: str, home: Path | None = None) -> str:
	if shell == "shim":
		directory = shell_quote_path(installed.parent, home, syntax)
		if syntax == "fish":
			return f"fish_add_path --prepend --move {directory}"
		return f'export PATH={directory}:"$PATH"'
	return f"source {shell_quote_path(installed, home, syntax)}"


def block(line: str) -> str:
	return f"{BEGIN}\n{line}\n{END}\n"


def block_spans(lines: list[str]) -> list[tuple[int, int]]:
	"""(begin, end) line indexes of every marker pair. Raises ValueError, naming the problem, when the markers do
	not form plain, non-nested pairs: an end without a begin, a begin inside a block, a begin left open."""
	spans: list[tuple[int, int]] = []
	start: int | None = None
	for number, line in enumerate(lines):
		marker = line.strip()
		if marker == BEGIN:
			if start is not None:
				raise ValueError(
					f"a begin marker on line {number + 1} sits inside the block begun on line {start + 1}"
				)
			start = number
		elif marker == END:
			if start is None:
				raise ValueError(f"an end marker on line {number + 1} has no begin marker")
			spans.append((start, number))
			start = None
	if start is not None:
		raise ValueError(f"the begin marker on line {start + 1} has no end marker")
	return spans


def has_block(text: str) -> bool:
	return bool(block_spans(text.splitlines()))


def add_block(rc: Path, line: str) -> bool:
	"""Append the block to rc unless it is already there. Returns True when the file changed. Raises ValueError,
	writing nothing, when the file's markers are not well formed (appending a second block to an unfinished one
	would make a later removal delete what lies between them)."""
	text = rc.read_text(encoding="utf-8") if rc.exists() else ""
	try:
		present = has_block(text)
	except ValueError as err:
		raise ValueError(f"{rc}: {err}; edit the file by hand") from None
	if present:
		return False
	if not rc.parent.exists():
		rc.parent.mkdir(parents=True, exist_ok=True)
	prefix = "" if not text or text.endswith("\n") else "\n"
	with open(rc, "a", encoding="utf-8") as fh:
		fh.write(prefix + block(line))
	return True


def remove_block(rc: Path) -> bool:
	"""Remove the block `add_block` wrote. Raises ValueError, and leaves the file untouched, when the markers are
	not well formed (someone edited the block): deleting a guessed region would destroy their config."""
	if not rc.exists():
		return False
	real = rc.resolve()  # write through a symlinked dotfile instead of replacing the link
	lines = real.read_text(encoding="utf-8").splitlines(keepends=True)
	try:
		spans = block_spans(lines)
	except ValueError as err:
		raise ValueError(f"{rc}: {err}; edit the file by hand") from None
	if spans:
		drop = {i for begin, end in spans for i in range(begin, end + 1)}
		out = [line for i, line in enumerate(lines) if i not in drop]
		fd, tmp = tempfile.mkstemp(prefix=f".{real.name}.", dir=real.parent)
		try:
			with os.fdopen(fd, "w", encoding="utf-8") as fh:
				fh.write("".join(out))
			shutil.copymode(real, tmp)
			os.replace(tmp, real)
		except BaseException:
			Path(tmp).unlink(missing_ok=True)
			raise
	return bool(spans)


def hook_command(
	shell: str,
	config_dir: Path,
	*,
	install: bool = False,
	uninstall: bool = False,
	rc: Path | None = None,
	yes: bool = False,
	out: TextIO | None = None,
	stdin: TextIO | None = None,
	home: Path | None = None,
) -> int:
	out, stdin = out or sys.stdout, stdin or sys.stdin
	home = home or Path.home()
	syntax = "fish" if shell == "fish" or (rc is not None and rc.name == "config.fish") else "posix"
	if rc is None and shell != "shim":
		rc = home / DEFAULT_RC[shell][2:]
	if uninstall:
		if rc is None:
			print(
				"hook shim --uninstall needs --rc FILE (the startup file the PATH line was added to)",
				file=sys.stderr,
			)
			return 2
		try:
			changed = remove_block(rc)
		except ValueError as err:
			print(f"{err} (end marker missing); nothing was changed", file=sys.stderr)
			return 2
		print(
			f"{'removed the omp-hindsight-guard lines from' if changed else 'nothing to remove in'} {rc}",
			file=out,
		)
		return 0
	installed = write_hook(shell, config_dir)
	line = startup_line(shell, installed, syntax, home)
	print(f"wrote {installed}", file=out)
	print("add this to your shell startup file:", file=out)
	print(f"    {line}", file=out)
	if shell == "shim":
		print(
			"(the shim finds the real omp further down PATH; use it instead of a function, not with one)",
			file=out,
		)
	if not install:
		return 0
	if rc is None:
		print("--install for the shim needs --rc FILE (where the PATH line should go)", file=sys.stderr)
		return 2
	print(f"--install will append to {rc}:", file=out)
	print(block(line), end="", file=out)
	if not yes:
		if not stdin.isatty():
			print("not appended: answer needs a terminal, or pass --yes", file=sys.stderr)
			return 2
		print("append? [y/N] ", end="", file=out, flush=True)
		if stdin.readline().strip().lower() not in ("y", "yes"):
			print("not appended", file=out)
			return 0
	try:
		changed = add_block(rc, line)
	except ValueError as err:
		print(f"{err}; nothing was changed", file=sys.stderr)
		return 2
	print(f"{'appended to' if changed else 'already present in'} {rc}; open a new shell to use it", file=out)
	return 0


def _git_exclude(repo: Path) -> Path | None:
	if not (repo / ".git").exists() or shutil.which("git") is None:
		return None
	try:
		proc = subprocess.run(
			["git", "-C", str(repo), "rev-parse", "--path-format=absolute", "--git-path", "info/exclude"],
			capture_output=True,
			text=True,
			timeout=10,
			check=False,
		)
	except (OSError, subprocess.SubprocessError):
		return None
	path = proc.stdout.strip()
	return Path(path) if proc.returncode == 0 and path else None


def link_repo(
	config: Config,
	overlays: Path,
	repo: Path,
	bank: str | None = None,
	home: Path | None = None,
	out: TextIO | None = None,
) -> int:
	"""Symlink <repo>/.omp/config.yml to the bank's overlay (per-repo mode, no shell hook needed)."""
	out = out or sys.stdout
	repo = repo.expanduser().resolve()
	if not repo.is_dir():
		print(f"{repo} is not a directory", file=sys.stderr)
		return 2
	if bank is None:
		bank = bank_for_path(repo, config.routes, home)
		if bank is None:
			print(f"{repo} is outside every bank root; pass --bank NAME", file=sys.stderr)
			return 2
	try:
		config.bank(bank)
	except ConfigError as err:
		print(str(err), file=sys.stderr)
		return 2
	overlay = overlays / f"{bank}.yml"
	if not overlay.is_file():
		print(f"{overlay} does not exist; run `omp-hindsight-guard overlays` first", file=sys.stderr)
		return 2
	if (repo / ".omp").is_symlink():
		print(f"{repo / '.omp'} is a symlink; link would write through it. Left alone", file=sys.stderr)
		return 2
	target = repo / ".omp" / "config.yml"
	if target.is_symlink() and Path(os.path.realpath(target)) == overlay.resolve():
		print(f"already linked: {target}", file=out)
	elif target.exists() or target.is_symlink():
		print(f"{target} already exists and is not this tool's link; left alone", file=sys.stderr)
		return 2
	else:
		target.parent.mkdir(exist_ok=True)
		target.symlink_to(overlay.resolve())
		print(f"linked {target} -> {overlay}", file=out)
	exclude = _git_exclude(repo)
	if exclude is None:
		print(
			f"not a git work tree (or no git): keep {EXCLUDE_LINE} out of version control yourself", file=out
		)
	else:
		exclude.parent.mkdir(parents=True, exist_ok=True)
		existing = exclude.read_text(encoding="utf-8") if exclude.exists() else ""
		if EXCLUDE_LINE not in existing.splitlines():
			with open(exclude, "a", encoding="utf-8") as fh:
				fh.write(("" if not existing or existing.endswith("\n") else "\n") + EXCLUDE_LINE + "\n")
			print(f"added {EXCLUDE_LINE} to {exclude}", file=out)
	print(LINK_NOTES, file=out)
	return 0


def unlink_repo(overlays: Path, repo: Path, out: TextIO | None = None) -> int:
	"""Remove <repo>/.omp/config.yml when it is a symlink into the overlay directory; nothing else."""
	out = out or sys.stdout
	repo = repo.expanduser().resolve()
	if (repo / ".omp").is_symlink():  # the same refusal as when linking: never reach through it
		print(f"{repo / '.omp'} is a symlink; left alone", file=sys.stderr)
		return 2
	target = repo / ".omp" / "config.yml"
	if not target.is_symlink():
		print(f"{target} is not a symlink; left alone", file=sys.stderr)
		return 2
	if Path(os.path.realpath(target)).parent != overlays.resolve():
		print(f"{target} does not point into {overlays}; left alone", file=sys.stderr)
		return 2
	target.unlink()
	try:
		target.parent.rmdir()
	except OSError:
		pass
	print(f"removed {target}", file=out)
	return 0
