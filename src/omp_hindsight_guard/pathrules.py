"""The few path rules every consumer shares (kept tiny so the hook helper starts fast)."""

from __future__ import annotations

import os
from pathlib import Path

ROUTES_NAME = "routes.tsv"


def canonical(path: str | Path) -> str:
	"""The form routing compares directories in: symlinks and `..` resolved, ASCII letters folded to lower case (and
	nothing else: every launcher folds exactly A-Z, so a Unicode sibling can never match differently in Python and
	in a shell), one trailing `/`."""
	return ascii_lower(os.path.realpath(os.path.expanduser(str(path))).rstrip("/")) + "/"


_ASCII_LOWER = {ord(c): ord(c) + 32 for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"}


def ascii_lower(text: str) -> str:
	return text.translate(_ASCII_LOWER)
