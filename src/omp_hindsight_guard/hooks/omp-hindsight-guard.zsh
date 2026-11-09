# omp memory bank by working directory (zsh). Source it from ~/.zshenv to cover terminals, multiplexer panes
# and `zsh -c`, or from ~/.zshrc for interactive shells only. Opt-in: nothing happens until it is sourced.
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
	emulate -L zsh
	if [[ $OMP_HINDSIGHT_GUARD_ON_DOWN == block ]]; then
		print -ru2 -- "omp: $1; refusing to start (OMP_HINDSIGHT_GUARD_ON_DOWN=block)"
		return 1
	fi
	[[ -n $OMP_HINDSIGHT_GUARD_QUIET ]] ||
		print -ru2 -- "omp: $1; running with omp's existing configuration (its memory destination is not enforced; OMP_HINDSIGHT_GUARD_ON_DOWN=block refuses to start instead)"
	return 0
}

omp() {
	emulate -L zsh
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
	if [[ -z $overlay ]]; then
		command omp "$@"
	elif [[ $1 == config ]]; then
		command env PI_CONFIG_FILES=$overlay omp "$@"
	else
		command env -u PI_CONFIG_FILES omp --config $overlay "$@"
	fi
}
