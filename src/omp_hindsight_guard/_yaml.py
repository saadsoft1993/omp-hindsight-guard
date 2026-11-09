"""PyYAML, imported on demand, with a clear failure when it is not installed."""

from __future__ import annotations

from types import ModuleType


class MissingDependency(RuntimeError):
	"""A declared dependency is not importable. The message names the package and how to install it."""


def require_yaml() -> ModuleType:
	try:
		import yaml
	except ImportError:
		raise MissingDependency(
			"PyYAML is required for this command but is not installed. "
			"Install the package with its dependencies (pipx/uv tool install omp-hindsight-guard) "
			"or run: python -m pip install 'PyYAML>=6.0'"
		) from None
	return yaml
