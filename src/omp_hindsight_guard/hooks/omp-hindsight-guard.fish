# omp memory bank by working directory (fish, 3.5 or newer). Put it in ~/.config/fish/conf.d/ or source it from
# config.fish. Opt-in: nothing happens until it is loaded.
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

function __ohg_unavailable
    if test "$OMP_HINDSIGHT_GUARD_ON_DOWN" = block
        echo "omp: $argv[1]; refusing to start (OMP_HINDSIGHT_GUARD_ON_DOWN=block)" >&2
        return 1
    end
    test -n "$OMP_HINDSIGHT_GUARD_QUIET"; or echo "omp: $argv[1]; running with omp's existing configuration (its memory destination is not enforced; OMP_HINDSIGHT_GUARD_ON_DOWN=block refuses to start instead)" >&2
    return 0
end

function omp
    set -l overlay (command omp-hindsight-guard-pick)
    set -l rc $status
    if test $rc -eq 75
        return 75
    else if test $rc -ne 0
        __ohg_unavailable "the routing helper omp-hindsight-guard-pick is not available (status $rc)"; or return 75
        set overlay ""
    end
    if test -z "$overlay"
        command omp $argv
    else if test "$argv[1]" = config
        command env PI_CONFIG_FILES=$overlay omp $argv
    else
        command env -u PI_CONFIG_FILES omp --config $overlay $argv
    end
end
