#!/usr/bin/env bash
# omp Hindsight outbox check: run it every few hours from cron, a systemd timer or launchd.
#
# omp queues explicit retain/learn writes in <outbox>/<destination>/ while Hindsight is unreachable, moves
# events undelivered for 7 days to quarantine/ and deletes them 30 days later. This reports (and notifies
# through osascript on macOS or notify-send on Linux, when present; nothing leaves the machine) when:
#   - any event is in a quarantine/ folder (lost unless re-sent by hand): exit 1;
#   - the outbox, or anything in it, is a symlink (the check would not look through it): exit 1;
#   - the outbox is accessible to group or other in any way (it holds queued memories in plain text): exit 1;
#   - a queued event is older than 72 hours: stale events are a warning (exit 0), not a failure.
# It also counts local mnemopi memories (written while Hindsight was unreachable) that the importer has not
# sent yet (`omp-hindsight-guard import --count-unsynced`) and notifies once a day while any are left. That
# count runs the importer, which reads and redacts those memories in memory to hash them (nothing is printed or
# sent). The outbox itself is only listed and counted, never opened. Prints counts only.
#
# Settings: HINDSIGHT_OUTBOX_DIR (default ~/.omp/agent/hindsight-outbox), OMP_MNEMOPI_ROOT (default
# ~/.omp/agent/memories/mnemopi/banks; the import is skipped when it is missing), OMP_HINDSIGHT_GUARD_BIN
# (default omp-hindsight-guard on PATH), OMP_HINDSIGHT_GUARD_STATE_DIR, OMP_HINDSIGHT_GUARD_NO_NOTIFY=1.
set -euo pipefail

outbox="${HINDSIGHT_OUTBOX_DIR:-$HOME/.omp/agent/hindsight-outbox}"
mnemopi="${OMP_MNEMOPI_ROOT:-$HOME/.omp/agent/memories/mnemopi/banks}"
guard="${OMP_HINDSIGHT_GUARD_BIN:-omp-hindsight-guard}"
state="${OMP_HINDSIGHT_GUARD_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/omp-hindsight-guard}"
stamp="$(date '+%Y-%m-%d %H:%M:%S')"

notify() {
	[[ -z "${OMP_HINDSIGHT_GUARD_NO_NOTIFY:-}" ]] || return 0
	if command -v osascript >/dev/null 2>&1; then
		# Escape for an AppleScript string: a path with a quote or backslash must not break out of it.
		local bs=$'\\' dq='"' text=$1
		text=${text//"$bs"/"$bs$bs"}
		text=${text//"$dq"/"$bs$dq"}
		osascript -e "display notification \"$text\" with title \"omp memory outbox\"" >/dev/null 2>&1 || true
	elif command -v notify-send >/dev/null 2>&1; then
		notify-send "omp memory outbox" "$1" >/dev/null 2>&1 || true
	fi
}

with_deadline() { # with_deadline <seconds> <command...>
	local seconds=$1
	shift
	if command -v timeout >/dev/null 2>&1; then
		timeout "$seconds" "$@"
	elif command -v perl >/dev/null 2>&1; then
		perl -e 'alarm shift; exec @ARGV or exit 127' "$seconds" "$@"
	else
		"$@"
	fi
}

# True when only you (or root) can change the path: the one implementation of that walk (lstat component by component,
# symlinks and `..` followed as the kernel does, ACLs inspected) is trustwalk.py next to the package. No Python: not
# trusted.
trusted() {
	local here
	here="$(cd "$(dirname "$0")" && pwd)"
	command "${HINDSIGHT_PYTHON:-python3}" "$here/../trustwalk.py" "$1" 2>/dev/null
}

# True when the state directory can be trusted with a file we later read back: not a symlink, ours, not writable
# by group or other (created private if missing). Otherwise the once-a-day limit is simply not applied.
state_ok() {
	[[ ! -L "$state" ]] || return 1
	[[ -d "$state" ]] || (umask 077 && mkdir -p "$state") 2>/dev/null || return 1
	[[ -d "$state" && ! -L "$state" && -O "$state" ]] || return 1
	local loose
	loose="$(find "$state" -maxdepth 0 \( -perm -020 -o -perm -002 \) 2>/dev/null)" || return 1 # a failed probe is "unsafe"
	[[ -z "$loose" ]] && trusted "$state"
}

sync=""
if command -v "$guard" >/dev/null 2>&1 && [[ -d $mnemopi ]]; then
	if count=$(with_deadline 60 "$guard" import --root "$mnemopi" --count-unsynced 2>/dev/null) &&
		[[ $count =~ ^unsynced=([0-9]+)$ ]]; then
		unsynced=${BASH_REMATCH[1]}
		if ((unsynced > 0)); then
			sync=" unsynced=$unsynced"
			notified="$state/mnemopi-unsynced-notified"
			today="$(date '+%Y-%m-%d')"
			seen=""
			if state_ok && [[ -f "$notified" && ! -L "$notified" && -O "$notified" ]]; then
				seen="$(cat "$notified" 2>/dev/null || true)"
			fi
			if [[ "$seen" != "$today" ]]; then
				notify "$unsynced local memories not yet in shared memory: rerun the mnemopi import"
				if state_ok && tmp_note="$(umask 077 && mktemp "$state/notified.XXXXXX")"; then
					# a fresh exclusive file renamed over the entry: a rename replaces a symlink, never follows it
					if printf '%s\n' "$today" >"$tmp_note" && mv -f "$tmp_note" "$notified"; then :; else rm -f "$tmp_note"; fi
				fi
			fi
		fi
	else
		sync=" unsynced=?"
	fi
fi

if [[ -L "$outbox" ]]; then
	echo "$stamp fail: $outbox is a symlink; set HINDSIGHT_OUTBOX_DIR to the directory itself$sync"
	exit 1
fi
[[ -d "$outbox" ]] || { echo "$stamp ok: no outbox$sync"; exit 0; }
if [[ -n "$(find "$outbox" -type l -print | head -n 1)" ]]; then
	echo "$stamp fail: the outbox contains a symlink (not followed, so its events are not counted)$sync"
	exit 1
fi

quarantined=$(find "$outbox" -path '*/quarantine/*' -type f | wc -l | tr -d ' ')
stale=$(find "$outbox" -name 'omp-*.json' -not -path '*/quarantine/*' -type f -mmin +4320 | wc -l | tr -d ' ')
queued=$(find "$outbox" -name 'omp-*.json' -not -path '*/quarantine/*' -type f | wc -l | tr -d ' ')

# The outbox holds queued (omp-redacted) memories in plain text: only this user may touch it. Any group or
# other permission bit (read, write or execute) counts.
any_other='( -perm -g=r -o -perm -g=w -o -perm -g=x -o -perm -o=r -o -perm -o=w -o -perm -o=x )'
# shellcheck disable=SC2086 # the expression is deliberately word-split into find arguments
open_dirs=$(find "$outbox" -type d $any_other | wc -l | tr -d ' ')
# shellcheck disable=SC2086
open_files=$(find "$outbox" -type f $any_other | wc -l | tr -d ' ')
if [[ $open_dirs -gt 0 || $open_files -gt 0 ]]; then
	notify "omp memory outbox is readable by other users: run chmod -R go-rwx $outbox"
	echo "$stamp fail: readable by others (dirs=$open_dirs files=$open_files)$sync"
	exit 1
fi
if [[ $quarantined -gt 0 ]]; then
	notify "$quarantined memory event(s) quarantined: Hindsight did not accept them for 7 days"
	echo "$stamp fail: quarantined=$quarantined queued=$queued stale=$stale$sync"
	exit 1
fi
if [[ $stale -gt 0 ]]; then
	notify "$stale memory event(s) waiting over 3 days: run /memory enqueue in omp when Hindsight is reachable"
	echo "$stamp warn: queued=$queued stale=$stale$sync"
	exit 0
fi
echo "$stamp ok: queued=$queued$sync"
