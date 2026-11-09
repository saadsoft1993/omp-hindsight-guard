#!/usr/bin/env bash
# PATH shim for omp: the same bank-by-folder logic as the shell functions, as an executable named `omp` that
# works in any shell, in `bash -c` and in multiplexer panes. Put the directory holding this file first in PATH
# (omp's own installer and self-update write elsewhere, so the shim is not overwritten). Use this OR a shell
# function, not both. Opt-in: nothing happens until the directory is on PATH.
#
# Thin by design: the decision is made by `omp-hindsight-guard-pick` (see omp-hindsight-guard.bash): this file only
# finds the real omp by walking PATH past its own directory (or uses OMP_HINDSIGHT_GUARD_REAL_OMP), asks the helper,
# and execs the real omp: with `--config <overlay>` and PI_CONFIG_FILES removed, or with PI_CONFIG_FILES for `omp
# config ...`, or untouched when no bank matches, the shared memory does not answer or the configuration cannot be
# trusted (its memory destination is then not enforced; OMP_HINDSIGHT_GUARD_ON_DOWN=block refuses to start, exit
# 75). Unlike the functions, an omp started by a session's tools goes through the shim again and so gets its
# folder's bank too.
#
# Settings: OMP_HINDSIGHT_GUARD_CONFIG_DIR, _OVERLAY_DIR, _ROUTES, _STATE_DIR, _ON_DOWN, _QUIET, _PROBE_TIMEOUT /
# _PROBE_UP_TTL / _PROBE_DOWN_TTL (read by the helper), OMP_HINDSIGHT_GUARD_REAL_OMP.

_ohg_real_omp() {
	local IFS=: self dir resolved
	if [ -n "${OMP_HINDSIGHT_GUARD_REAL_OMP:-}" ]; then
		printf '%s\n' "$OMP_HINDSIGHT_GUARD_REAL_OMP"
		return 0
	fi
	self=$(cd -P -- "$(dirname -- "$0")" 2>/dev/null && pwd -P)
	for dir in $PATH; do
		[ -n "$dir" ] || continue
		resolved=$(cd -P -- "$dir" 2>/dev/null && pwd -P) || continue
		[ "$resolved" = "$self" ] && continue
		if [ -x "$dir/omp" ] && [ ! -d "$dir/omp" ]; then
			printf '%s\n' "$dir/omp"
			return 0
		fi
	done
	return 1
}

real=$(_ohg_real_omp) || {
	printf 'omp (omp-hindsight-guard shim): no real omp found on PATH; set OMP_HINDSIGHT_GUARD_REAL_OMP\n' >&2
	exit 127
}
rc=0
overlay=$(command omp-hindsight-guard-pick) || rc=$?
case $rc in
0) ;;
75) exit 75 ;;
*)
	if [ "${OMP_HINDSIGHT_GUARD_ON_DOWN:-}" = block ]; then
		printf 'omp: the routing helper omp-hindsight-guard-pick is not available (status %s); refusing to start (OMP_HINDSIGHT_GUARD_ON_DOWN=block)\n' "$rc" >&2
		exit 75
	fi
	[ -n "${OMP_HINDSIGHT_GUARD_QUIET:-}" ] ||
		printf "omp: the routing helper omp-hindsight-guard-pick is not available (status %s); running with omp's existing configuration (its memory destination is not enforced; OMP_HINDSIGHT_GUARD_ON_DOWN=block refuses to start instead)\\n" "$rc" >&2
	overlay=
	;;
esac
if [ -z "$overlay" ]; then
	exec "$real" "$@"
elif [ "${1:-}" = config ]; then
	export PI_CONFIG_FILES=$overlay
	exec "$real" "$@"
else
	unset PI_CONFIG_FILES
	exec "$real" --config "$overlay" "$@"
fi
