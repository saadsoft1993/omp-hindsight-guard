"""Which memory bank a directory belongs to, from the roots in banks.json.

The shell hooks read the same table (routes.tsv, written by `omp-hindsight-guard overlays`) with the same rules:
resolve symlinks, compare case-insensitively, longest root wins, no match means no shared memory. Two banks with
equally long matching roots are an error, never a choice made by file order: no bank is selected.
"""

from __future__ import annotations

import dataclasses
import os
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from omp_hindsight_guard.pathrules import ROUTES_NAME, canonical

if TYPE_CHECKING:
	from omp_hindsight_guard.config import Config

Banks = Sequence[tuple[str, str]]


@dataclasses.dataclass(frozen=True)
class Route:
	bank: str | None
	missing_cwd: bool
	ambiguous: bool = False
	candidates: tuple[str, ...] = ()  # the banks that matched equally well, in table order (when ambiguous)


def expand_root(root: str, home: Path | str) -> Path:
	"""A banks.json root (`~/...` or absolute) as a path; `~` means `home`."""
	return Path(home) / root[2:] if root.startswith("~/") else Path(root)


def route(path: Path | str, banks: Banks, home: Path | str | None = None) -> Route:
	"""Bank for path, and whether path no longer exists (it is then routed by its normalised string)."""
	home = Path.home() if home is None else Path(home)
	try:
		target = canonical(path)
		prefixes = [(bank, canonical(expand_root(root, home))) for bank, root in banks]
	except ValueError:  # an embedded NUL byte in a path read from a database
		return Route(None, True)
	best = 0
	winners: list[str] = []
	for bank, prefix in prefixes:
		if not target.startswith(prefix):
			continue
		if len(prefix) > best:
			best, winners = len(prefix), [bank]
		elif len(prefix) == best:
			if bank not in winners:
				winners.append(bank)
	missing = not os.path.exists(path)
	if len(winners) > 1:
		return Route(None, missing, True, tuple(winners))
	return Route(next(iter(winners)) if winners else None, missing)


def bank_for_path(path: Path | str, banks: Banks, home: Path | str | None = None) -> str | None:
	return route(path, banks, home).bank


def routes_table(config: Config) -> str:
	"""routes.tsv: one `<bank><TAB><root>` line per root. Roots never contain a tab or a newline."""
	return "".join(f"{bank}\t{root}\n" for bank, root in config.routes)


def routes_path(overlay_dir: Path) -> Path:
	return overlay_dir / ROUTES_NAME
