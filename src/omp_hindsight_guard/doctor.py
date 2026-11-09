"""`omp-hindsight-guard doctor`: does the setup on this machine do what it is meant to do?

Static checks (configuration, key files, overlays, route table) and, unless --offline, live checks against the
proxy: it answers, refuses requests without a key, accepts each bank's key for that bank only (own bank 200,
every other bank 404, `/docs` 404) and never accepts Hindsight's own key. Keys are never printed. Exit code 0
when nothing failed (warnings are allowed), 1 when something failed, 2 when the configuration cannot be loaded.
"""

from __future__ import annotations

import dataclasses
import hmac
import os
import re
import shutil
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from pathlib import Path
from typing import TextIO

from omp_hindsight_guard._yaml import MissingDependency, require_yaml
from omp_hindsight_guard.config import (
	Config,
	ConfigError,
	Keys,
	default_config_path,
	load_config,
	load_keys,
	overlay_dir,
	read_key,
)
from omp_hindsight_guard.overlays import check_api_url, read_overlay, stale_overlays
from omp_hindsight_guard.routing import expand_root, routes_path, routes_table

TIMEOUT = 5
UNKNOWN_BANK = "doctor-no-such-bank"


@dataclasses.dataclass
class Result:
	level: str  # ok | warn | fail
	name: str
	detail: str = ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
	def redirect_request(self, req, fp, code, msg, headers, newurl):
		return None


_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def http_status(url: str, key: str | None = None) -> int:
	"""Status code of a GET (0 when the server cannot be reached). Never follows a redirect."""
	req = urllib.request.Request(url, headers={"Authorization": f"Bearer {key}"} if key else {})
	try:
		with _opener.open(req, timeout=TIMEOUT) as resp:
			return resp.status
	except urllib.error.HTTPError as err:
		err.close()
		return err.code
	except (urllib.error.URLError, OSError, ValueError):
		return 0


def _mode(path: Path) -> int:
	return stat.S_IMODE(path.stat().st_mode)


def check_static(
	config: Config, overlays: Path, home: Path | None = None
) -> tuple[list[Result], Keys | None]:
	out: list[Result] = []
	home = home or Path.home()
	try:
		require_yaml()
		out.append(Result("ok", "PyYAML is installed"))
	except MissingDependency as err:
		out.append(Result("fail", "PyYAML is installed", str(err)))
	if shutil.which("omp-hindsight-guard-pick") is None:
		out.append(
			Result(
				"warn",
				"omp-hindsight-guard-pick is on PATH",
				"the shell hooks and the shim call it; without it they run omp unchanged (or refuse with block)",
			)
		)
	if shutil.which("omp") is None:
		out.append(Result("warn", "omp is on PATH", "not found by this shell"))
	if _mode(config.path) & 0o022:
		out.append(Result("fail", "banks.json permissions", f"{config.path} is writable by group or other"))
	else:
		out.append(Result("ok", "banks.json is not writable by others"))

	keys: Keys | None = None
	try:
		keys = load_keys(config)
		out.append(Result("ok", "key files", f"{len(keys.banks) + 1} keys, 0600, distinct"))
	except ConfigError as err:
		out.append(Result("fail", "key files", str(err)))
		# Narrow it down: one line per unusable key file.
		for what, path in [("upstream", config.proxy.upstream_key_file)] + [
			(b.name, b.key_file) for b in config.banks
		]:
			try:
				read_key(path, what)
			except ConfigError as inner:
				out.append(Result("fail", f"key file {what}", str(inner)))
	for bank in config.banks:
		if not bank.roots:
			out.append(
				Result(
					"warn", f"bank {bank.name} roots", "no roots: only `link --bank` or the importer reach it"
				)
			)
		for root in bank.roots:
			if not expand_root(root, home).is_dir():
				out.append(
					Result("warn", f"bank {bank.name} root", f"{root} is not a directory on this machine")
				)

	if not overlays.is_dir():
		out.append(
			Result(
				"fail", "overlay directory", f"{overlays} does not exist; run `omp-hindsight-guard overlays`"
			)
		)
		return out, keys
	if _mode(overlays) & 0o077:
		out.append(Result("fail", "overlay directory mode", f"{overlays} must be 0700"))
	else:
		out.append(Result("ok", "overlay directory is private"))
	for bank in config.banks:
		path = overlays / f"{bank.name}.yml"
		name = f"overlay {bank.name}"
		if not path.is_file():
			out.append(Result("fail", name, f"{path} is missing; run `omp-hindsight-guard overlays`"))
			continue
		try:
			overlay = read_overlay(path)
			url, token = overlay.url, overlay.token
		except (OSError, ValueError) as err:
			out.append(Result("fail", name, str(err)))
			continue
		except MissingDependency:
			continue  # already reported above
		problems = []
		if overlay.bank != bank.name:
			problems.append("bankId does not match")
		if keys is not None and not hmac.compare_digest(token.encode(), keys.banks[bank.name].encode()):
			problems.append("token differs from the key file (run `overlays` again)")
		try:
			check_api_url(url)
		except ValueError as err:
			problems.append(str(err))
		out.append(Result("fail", name, "; ".join(problems)) if problems else Result("ok", name, f"-> {url}"))
	for path in stale_overlays(config, overlays):
		out.append(
			Result("warn", "stale overlay", f"{path.name} is not a bank in banks.json (`overlays --prune`)")
		)
	table = routes_path(overlays)
	try:
		current = table.read_text(encoding="utf-8") == routes_table(config)
	except OSError:
		current = False
	if current:
		out.append(Result("ok", "routes.tsv matches banks.json"))
	else:
		out.append(
			Result(
				"fail", "routes.tsv", "missing or older than banks.json; run `omp-hindsight-guard overlays`"
			)
		)
	return out, keys


def check_live(config: Config, keys: Keys, proxy_url: str) -> list[Result]:
	out: list[Result] = []
	proxy_url = proxy_url.rstrip("/")
	try:
		check_api_url(proxy_url)  # the same rule as for overlays: https anywhere, http only to this machine
	except ValueError as err:
		return [Result("fail", "proxy-url", f"{err}; no key was sent")]
	local = urllib.parse.urlsplit(proxy_url).hostname in ("127.0.0.1", "localhost", "::1")
	if not local:
		out.append(
			Result(
				"warn",
				"proxy-url",
				"remote proxy: Hindsight's own key is not sent to it, so that check is skipped",
			)
		)
	health = http_status(f"{proxy_url}/health/ready")
	if health != 200:
		out.append(
			Result("fail", "proxy /health/ready", f"{proxy_url} answered {health or 'nothing'}, expected 200")
		)
		return out
	out.append(Result("ok", "proxy /health/ready", "200"))
	listing = "/v1/default/banks/{}/memories/list"
	for bank in config.banks:
		url = proxy_url + listing.format(bank.name)
		problems = []
		if (code := http_status(url)) != 401:
			problems.append(f"no key -> {code}, expected 401")
		if local and (code := http_status(url, keys.upstream)) != 401:
			problems.append(f"Hindsight's own key -> {code}, expected 401")
		own = http_status(url, keys.banks[bank.name])
		# Hindsight creates a bank on its first write: until then its own listing answers 404, which proves nothing either way.
		unborn = own == 404
		if own != 200 and not unborn:
			problems.append(f"own key on own bank -> {own}, expected 200")
		for other in [b.name for b in config.banks if b.name != bank.name] + [UNKNOWN_BANK]:
			if (code := http_status(proxy_url + listing.format(other), keys.banks[bank.name])) != 404:
				label = "an unconfigured bank" if other == UNKNOWN_BANK else f"bank {other}"
				problems.append(f"own key on {label} -> {code}, expected 404")
		if (code := http_status(f"{proxy_url}/docs", keys.banks[bank.name])) != 404:
			problems.append(f"own key on /docs -> {code}, expected 404")
		name = f"isolation {bank.name}"
		if problems:
			out.append(Result("fail", name, "; ".join(problems)))
		elif unborn:
			out.append(
				Result(
					"warn",
					name,
					"own bank answered 404: Hindsight has not created it yet (it does on the first write); "
					"the other isolation checks passed. Run doctor again after the first retain",
				)
			)
		else:
			checked = "no key 401" + ("; upstream key 401" if local else "")
			skipped = (
				"" if local else " (Hindsight's own key was NOT probed: the proxy is not on this machine)"
			)
			out.append(
				Result(
					"ok",
					name,
					f"own key: own bank 200, other banks and /docs 404; {checked}{skipped}",
				)
			)
	return out


def check_backup(
	directory: Path, max_age_hours: float, config: Config | None = None, export_max_age_days: float = 8
) -> list[Result]:
	dumps = (
		sorted(directory.glob("hindsight-*.dump"), key=lambda p: p.stat().st_mtime)
		if directory.is_dir()
		else []
	)
	if not dumps:
		return [Result("fail", "backup", f"no hindsight-*.dump in {directory}")]
	age = (time.time() - dumps[-1].stat().st_mtime) / 3600
	if age > max_age_hours:
		return [Result("fail", "backup", f"newest dump is {age:.0f} h old (limit {max_age_hours:g} h)")]
	out = [Result("ok", "backup", f"newest dump is {age:.1f} h old")]
	# How long backups have been running: from the date backup.sh recorded once (retention prunes old dumps, so the
	# oldest dump would keep moving forward), else from the oldest dump still there.
	began = dumps[0].stat().st_mtime
	try:
		recorded = int((directory / ".first-run").read_text().strip())
		began = min(began, recorded)
	except (OSError, ValueError):
		pass
	oldest_days = (time.time() - began) / 86400
	for bank in config.banks if config else ():
		# Exactly `export-<bank>-<date>-<six digit time>.zip`: a bank named `work-old` must not count as an
		# export of `work`.
		pattern = re.compile(rf"export-{re.escape(bank.name)}-\d{{4}}-\d{{2}}-\d{{2}}-\d{{6}}\.zip")
		exports = [p for p in directory.iterdir() if pattern.fullmatch(p.name)]
		name = f"export {bank.name}"
		if not exports:
			# A weekly export has had a full cycle by the time the oldest dump is older than its limit: past
			# that, no export means the bank is not protected, which is a failure, not a reminder.
			past = oldest_days > export_max_age_days
			text = f"no export although backups began {oldest_days:.0f} d ago" if past else "no export yet"
			out.append(Result("fail" if past else "warn", name, text))
			continue
		days = (time.time() - max(p.stat().st_mtime for p in exports)) / 86400
		if days > export_max_age_days:
			out.append(
				Result("fail", name, f"newest export is {days:.0f} d old (limit {export_max_age_days:g} d)")
			)
		else:
			out.append(Result("ok", name, f"newest export is {days:.1f} d old"))
	return out


def run_doctor(
	config_path: Path | None = None,
	*,
	env: Mapping[str, str] | None = None,
	out: TextIO | None = None,
	proxy_url: str | None = None,
	offline: bool = False,
	backup_dir: Path | None = None,
	backup_max_age_hours: float = 26,
	home: Path | None = None,
) -> int:
	out = out or sys.stdout
	env = os.environ if env is None else env
	try:
		config = load_config(config_path or default_config_path(env), env)
	except ConfigError as err:
		print(f"fail config: {err}", file=out)
		return 2
	results = [Result("ok", "banks.json", f"{len(config.banks)} bank(s) in {config.path}")]
	static, keys = check_static(config, overlay_dir(env, home), home)
	results += static
	if not offline:
		if keys is None:
			results.append(Result("fail", "proxy checks", "skipped: the keys could not be loaded"))
		else:
			results += check_live(config, keys, proxy_url or config.proxy.local_url)
	if backup_dir is not None:
		results += check_backup(backup_dir, backup_max_age_hours, config)
	for r in results:
		print(f"{r.level:<4} {r.name}" + (f": {r.detail}" if r.detail else ""), file=out)
	counts = {level: sum(r.level == level for r in results) for level in ("ok", "warn", "fail")}
	print(f"{counts['ok']} ok, {counts['warn']} warning(s), {counts['fail']} failure(s)", file=out)
	return 1 if counts["fail"] else 0
