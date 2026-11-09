#!/usr/bin/env bash
# Hindsight backup: run it from cron, a systemd timer or launchd (also safe to run by hand).
#
# - pg_dump -Fc of the Hindsight database WITHOUT llm_requests rows (prompt traces are off in the documented
#   setup; this keeps any that appear out of the dumps) into the backup directory (0700, files 0600); the
#   newest HINDSIGHT_KEEP_DUMPS (14) are kept.
# - On HINDSIGHT_EXPORT_DAY (ISO weekday, default 7 = Sunday) or with HINDSIGHT_EXPORT=1: `hindsight-admin
#   export-bank` per bank, the newest HINDSIGHT_KEEP_EXPORTS (8) per bank kept. A failed or invalid export is
#   logged, its partial file removed, and the run exits non-zero.
# - Exports are the only per-bank protection, so a run with no banks to export fails (after the dump) unless
#   HINDSIGHT_NO_EXPORT=1 says that is intended: a missing configuration must not look like a healthy backup.
# A dump is kept only if pg_restore can list it and it has the documents table; an export only if Python's zipfile
# reads every member and its checksum. Both are written under a temporary name and renamed once complete, so a
# half-written file never has a final name. Otherwise the old files stay and the run exits non-zero
# (`omp-hindsight-guard doctor --backup-dir` fails when the newest dump or export is too old).
# Only one backup runs at a time: an exclusive kernel lock (flock, released when the process ends, so a crash
# leaves nothing to clean up) on .backup.lock in the backup directory. That directory must be new, empty or hold
# only this script's own files, must not be a symlink and must be yours. Needs python3 (HINDSIGHT_PYTHON).
#
# Settings (environment; `omp-hindsight-guard backup` fills HINDSIGHT_BANKS from banks.json):
#   HINDSIGHT_PG_BIN        directory holding pg_dump and pg_restore. Default: whatever is on PATH. Homebrew's
#                           versioned keg is not on PATH: /opt/homebrew/opt/postgresql@17/bin (Apple silicon)
#                           or /usr/local/opt/postgresql@17/bin (Intel); Debian and Ubuntu put them on PATH.
#   HINDSIGHT_CONF_DIR      holds .pgpass and the server's .env. Default: ~/.config/hindsight
#   HINDSIGHT_PGPASSFILE    default: $HINDSIGHT_CONF_DIR/.pgpass
#   HINDSIGHT_PG_HOST / _PORT / _USER / _DB   defaults 127.0.0.1 / 5432 / hindsight / hindsight
#   HINDSIGHT_BACKUP_DIR    default: <state dir>/backups
#   HINDSIGHT_BANKS         space-separated bank names to export
#   HINDSIGHT_ADMIN         hindsight-admin, run as given (default: the hsadmin.sh next to this file)
#   HINDSIGHT_KEEP_DUMPS, HINDSIGHT_KEEP_EXPORTS   integers from 1 to 9999 (a zero would delete every file)
#   HINDSIGHT_EXPORT_DAY, HINDSIGHT_EXPORT=1, HINDSIGHT_NO_EXPORT=1, HINDSIGHT_PYTHON (default python3)
set -euo pipefail
umask 077

here="$(cd "$(dirname "$0")" && pwd)"
conf="${HINDSIGHT_CONF_DIR:-$HOME/.config/hindsight}"
state="${OMP_HINDSIGHT_GUARD_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/omp-hindsight-guard}"
out="${HINDSIGHT_BACKUP_DIR:-$state/backups}"
pg_dump_bin="${HINDSIGHT_PG_BIN:+$HINDSIGHT_PG_BIN/}pg_dump"
pg_restore_bin="${HINDSIGHT_PG_BIN:+$HINDSIGHT_PG_BIN/}pg_restore"
pg_host="${HINDSIGHT_PG_HOST:-127.0.0.1}"
pg_port="${HINDSIGHT_PG_PORT:-5432}"
pg_user="${HINDSIGHT_PG_USER:-hindsight}"
pg_db="${HINDSIGHT_PG_DB:-hindsight}"
read -r -a banks <<<"${HINDSIGHT_BANKS:-}"
keep_dumps="${HINDSIGHT_KEEP_DUMPS-14}"
keep_exports="${HINDSIGHT_KEEP_EXPORTS-8}"
export_day="${HINDSIGHT_EXPORT_DAY:-7}"
if [[ -n "${HINDSIGHT_ADMIN:-}" ]]; then
	admin_cmd=("$HINDSIGHT_ADMIN") # run as given: a binary, a script with a shebang, anything executable
else
	admin_cmd=(bash "$here/hsadmin.sh")
fi

# Retention counts first, before anything can be deleted: 0, a negative number, text or a number too large for
# the shell's arithmetic (it wraps negative and then "keeps none") must never be accepted.
for var in HINDSIGHT_KEEP_DUMPS HINDSIGHT_KEEP_EXPORTS; do
	value="${!var-1}"
	if [[ ! "$value" =~ ^[1-9][0-9]{0,3}$ ]]; then
		echo "$var must be an integer from 1 to 9999, not '$value'" >&2
		exit 2
	fi
done
py="${HINDSIGHT_PYTHON:-python3}"
if ! command -v "$py" >/dev/null 2>&1; then
	echo "python3 is required (the backup lock and the archive check); set HINDSIGHT_PYTHON" >&2
	exit 2
fi

export PGPASSFILE="${HINDSIGHT_PGPASSFILE:-$conf/.pgpass}"
# Only use a directory that is ours, is not a symlink and holds nothing but this script's own files: a symlinked
# or foreign directory would be chmod'd and written into (HINDSIGHT_BACKUP_DIR=$HOME must never happen).
if [[ -L "$out" ]]; then
	echo "$out is a symlink; set HINDSIGHT_BACKUP_DIR to the directory itself" >&2
	exit 1
fi
if [[ -e "$out" ]]; then
	if [[ ! -d "$out" || ! -O "$out" ]]; then
		echo "$out is not a backup directory (it is not a directory of yours)" >&2
		exit 1
	fi
	if [[ -n "$(find "$out" -mindepth 1 -maxdepth 1 ! -name 'hindsight-*.dump' ! -name 'export-*.zip' ! -name '.hindsight-*' ! -name '.export-*' ! -name '.backup.lock' ! -name '.first-run' -print | head -n 1)" ]]; then
		echo "$out is not a backup directory (it holds other files); set HINDSIGHT_BACKUP_DIR to a new or empty directory" >&2
		exit 1
	fi
fi
# Only a location nobody else could replace: every directory above it (and the symlinks on the way) is yours or
# root's with no write access for others, ACLs included (trustwalk.py). Checked before anything is created and again
# once the directory exists, because everything below uses pathnames and relies on that.
trust="$here/../trustwalk.py"
if ! "$py" "$trust" "$out" 2>/dev/null; then
	echo "$out is not in a trusted location (a directory above it can be changed by someone else, or by an ACL)" >&2
	exit 1
fi
mkdir -p "$out"
chmod 700 "$out"
if ! "$py" "$trust" "$out" 2>/dev/null; then
	echo "$out is not in a trusted location after it was created" >&2
	exit 1
fi
stamp="$(date +%Y-%m-%d-%H%M%S)"
# When backups began, kept apart from the dumps (retention prunes those): `doctor` measures the grace for a first
# export from it. Written once, never rewritten.
[[ -e "$out/.first-run" ]] || (set -o noclobber && date +%s >"$out/.first-run") 2>/dev/null || true
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*"; }

# One backup at a time, by a kernel lock: lockrun.py takes flock on .backup.lock and then runs this script again
# with the lock held. There is no pid file to guess about and no lock file to delete, so nothing can be stolen
# or left behind by a crash.
lock="$out/.backup.lock"
if [[ "${OHG_BACKUP_LOCK_HELD:-}" != "$lock" ]]; then
	exec "$py" "$here/lockrun.py" "$lock" "${BASH:-bash}" "$0" "$@"
fi
tmp=""
tmpdir=""
# shellcheck disable=SC2317,SC2329 # invoked by the EXIT trap
cleanup() {
	[[ -z "$tmp" ]] || rm -f "$tmp"
	[[ -z "$tmpdir" ]] || rm -rf "$tmpdir"
}
trap cleanup EXIT

# GNU stat takes -c, BSD/macOS stat takes -f.
if stat -c %s / >/dev/null 2>&1; then
	file_size() { stat -c %s "$1"; }
else
	file_size() { stat -f %z "$1"; }
fi

# A zip archive that Python's zipfile can read completely: the central directory, and every member's checksum.
valid_zip() {
	"$py" - "$1" <<'PY' >/dev/null 2>&1
import sys
import zipfile

with zipfile.ZipFile(sys.argv[1]) as archive:
    sys.exit(1 if archive.testzip() is not None else 0)
PY
}

tmp="$(mktemp "$out/.hindsight-partial.XXXXXX")"
"$pg_dump_bin" -Fc -w -h "$pg_host" -p "$pg_port" -U "$pg_user" --exclude-table-data='*.llm_requests' -f "$tmp" "$pg_db"
# Read the table of contents fully before grepping: `grep -q` exits at the first match and, under pipefail, the
# writer's SIGPIPE would fail a good dump with a large table of contents.
toc="$("$pg_restore_bin" -l "$tmp")"
if ! grep -Eq 'TABLE [^ ]+ documents ' <<<"$toc"; then
	log "fail: dump has no documents table, old dumps kept"
	exit 1
fi
mv "$tmp" "$out/hindsight-$stamp.dump"
tmp=""
log "ok: hindsight-$stamp.dump ($(file_size "$out/hindsight-$stamp.dump") bytes)"

prune() { # prune <name pattern> <keep>: delete all but the newest <keep> files in $out matching the pattern
	local f n=0
	# shellcheck disable=SC2086 # the pattern is meant to glob
	while IFS= read -r f; do
		n=$((n + 1))
		if ((n > $2)); then rm -f -- "$out/$f"; fi
	done < <(cd "$out" && ls -1t -- $1 2>/dev/null)
}
prune "hindsight-*.dump" "$keep_dumps"

failed=0
if [[ ${#banks[@]} -eq 0 && "${HINDSIGHT_NO_EXPORT:-0}" != 1 ]]; then
	log "fail: no banks configured, so nothing is exported (set HINDSIGHT_BANKS, or HINDSIGHT_NO_EXPORT=1 if that is intended)"
	failed=1
fi
if [[ "$(date +%u)" == "$export_day" || "${HINDSIGHT_EXPORT:-0}" == 1 ]]; then
	for bank in "${banks[@]+"${banks[@]}"}"; do
		if [[ ! "$bank" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]]; then
			log "fail: bank name '$bank' is not a valid bank name"
			failed=1
			continue
		fi
		tmpdir="$(mktemp -d "$out/.export-partial.XXXXXX")"
		if "${admin_cmd[@]}" export-bank -b "$bank" -o "$tmpdir/export.zip" >/dev/null; then
			if valid_zip "$tmpdir/export.zip"; then
				mv "$tmpdir/export.zip" "$out/export-$bank-$stamp.zip"
				log "ok: export-$bank-$stamp.zip"
				# Prune this bank only after a validated export was promoted: a failed run keeps every older one.
				# Exactly `export-<bank>-<date>-<six digit time>.zip`: the bank `a` must never match the export of
				# a bank named `a-2026-11-09-123456`.
				prune "export-$bank-[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9].zip" "$keep_exports"
			else
				log "fail: export-bank $bank wrote something that is not a valid archive"
				failed=1
			fi
		else
			log "fail: export-bank $bank"
			failed=1
		fi
		rm -rf "$tmpdir"
		tmpdir=""
	done
fi
exit "$failed"
