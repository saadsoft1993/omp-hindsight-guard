#!/usr/bin/env bash
# hindsight-admin, always run from the directory that holds Hindsight's .env. Started anywhere else it finds no
# HINDSIGHT_API_DATABASE_URL and silently works on an empty embedded database instead.
#
#   omp-hindsight-guard hsadmin worker-status
#   omp-hindsight-guard hsadmin export-bank -b work -o /path/to/work.zip
#
# Settings: HINDSIGHT_CONF_DIR (default ~/.config/hindsight), HINDSIGHT_ADMIN_BIN (default: hindsight-admin on
# PATH, else ~/.local/bin/hindsight-admin). Provider-specific variables (for example a dedicated login
# directory for the model provider) belong in the .env file or in the environment of the caller.
set -euo pipefail
conf="${HINDSIGHT_CONF_DIR:-$HOME/.config/hindsight}"
cd "$conf" 2>/dev/null || { echo "no $conf (set HINDSIGHT_CONF_DIR)" >&2; exit 1; }
[[ -r .env ]] || { echo "no $conf/.env" >&2; exit 1; }
admin="${HINDSIGHT_ADMIN_BIN:-}"
if [[ -z $admin ]]; then
	if command -v hindsight-admin >/dev/null 2>&1; then
		admin="$(command -v hindsight-admin)"
	else
		admin="$HOME/.local/bin/hindsight-admin"
	fi
fi
exec "$admin" "$@"
