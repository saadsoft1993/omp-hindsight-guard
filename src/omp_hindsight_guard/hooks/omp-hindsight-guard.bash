# omp memory bank by working directory (bash, 3.2 or newer). Source it from ~/.bashrc (interactive shells) or
# from the file named by BASH_ENV (scripts). Opt-in: nothing happens until it is sourced. Use this OR the PATH
# shim, not both.
#
# This file is deliberately thin. The decision (which bank, which overlay, whether the shared memory answers) is
# made by `omp-hindsight-guard-pick`, which runs in the folder omp is started in: it parses the routing table
# strictly, compares folders exactly as the importer does, refuses any file or directory that someone else could
# replace (symlinks, ACLs), and probes the server with a short timeout and a cache. It prints the overlay path
# (empty: run omp unchanged); exit status 75 means refuse to start (OMP_HINDSIGHT_GUARD_ON_DOWN=block). The overlay
# goes to omp as `--config <overlay>` with PI_CONFIG_FILES removed, `omp config ...` gets PI_CONFIG_FILES instead.
# When the helper is not on PATH the launch is treated like any other "cannot tell": omp runs unchanged with a
# notice (its memory destination is then not enforced), or is refused under block.
#
# Settings: OMP_HINDSIGHT_GUARD_CONFIG_DIR, _OVERLAY_DIR, _ROUTES, _STATE_DIR, _ON_DOWN=block, _QUIET,
# _PROBE_TIMEOUT / _PROBE_UP_TTL / _PROBE_DOWN_TTL (read by the helper).

_ohg_unavailable() {
	if [ "${OMP_HINDSIGHT_GUARD_ON_DOWN:-}" = block ]; then
		printf 'omp: %s; refusing to start (OMP_HINDSIGHT_GUARD_ON_DOWN=block)\n' "$1" >&2
		return 1
	fi
	[ -n "${OMP_HINDSIGHT_GUARD_QUIET:-}" ] ||
		printf "omp: %s; running with omp's existing configuration (its memory destination is not enforced; OMP_HINDSIGHT_GUARD_ON_DOWN=block refuses to start instead)\\n" "$1" >&2
	return 0
}

omp() {
	local overlay rc=0
	overlay=$(command omp-hindsight-guard-pick) || rc=$?
	case $rc in
	0) ;;
	75) return 75 ;;
	*)
		_ohg_unavailable "the routing helper omp-hindsight-guard-pick is not available (status $rc)" || return 75
		overlay=
		;;
	esac
	if [ -z "$overlay" ]; then
		command omp "$@"
	elif [ "${1:-}" = config ]; then
		command env PI_CONFIG_FILES="$overlay" omp "$@"
	else
		command env -u PI_CONFIG_FILES omp --config "$overlay" "$@"
	fi
}
