#!/usr/bin/env bash
# Count, per table, the rows of the Hindsight database whose full row text contains each needle. Prints counts
# only (needles by position, never row contents). Used for the redaction canary (fake credentials sent through
# the proxy must count 0 in every table) and for bank-isolation markers.
#
#   omp-hindsight-guard canary-count <needle> [<needle> ...]     # "#1 none", "#2 chunks=1 ..."
#   omp-hindsight-guard canary-count --by-bank <needle> [...]    # documents per bank_id
#
# Settings: HINDSIGHT_PG_BIN (directory holding psql; default PATH), HINDSIGHT_CONF_DIR (default
# ~/.config/hindsight, holds .pgpass), HINDSIGHT_PGPASSFILE, HINDSIGHT_PG_HOST / _PORT / _USER / _DB.
set -euo pipefail
conf="${HINDSIGHT_CONF_DIR:-$HOME/.config/hindsight}"
export PGPASSFILE="${HINDSIGHT_PGPASSFILE:-$conf/.pgpass}"
psql=("${HINDSIGHT_PG_BIN:+$HINDSIGHT_PG_BIN/}psql" -X -w -q
	-h "${HINDSIGHT_PG_HOST:-127.0.0.1}" -p "${HINDSIGHT_PG_PORT:-5432}"
	-U "${HINDSIGHT_PG_USER:-hindsight}" -d "${HINDSIGHT_PG_DB:-hindsight}" -At -v ON_ERROR_STOP=1)

by_bank=0
[[ "${1:-}" == "--by-bank" ]] && { by_bank=1; shift; }
i=0
for needle in "$@"; do
	i=$((i + 1))
	if [[ $by_bank -eq 1 ]]; then
		out=$("${psql[@]}" -v needle="$needle" <<'SQL'
select coalesce(string_agg(bank_id || '=' || n, ' ' order by bank_id), 'none')
from (select bank_id, count(*) n from documents where strpos(documents::text, :'needle') > 0 group by bank_id) s;
SQL
)
	else
		# A DO block cannot read psql variables, so the needle travels in a session setting.
		out=$("${psql[@]}" -v needle="$needle" <<'SQL'
select set_config('canary.needle', :'needle', false) is null as unused \gset
create temp table _hits (tbl text, n bigint);
do $$
declare t record; n bigint;
begin
	for t in select tablename from pg_tables where schemaname = 'public' loop
		execute format('select count(*) from public.%I x where strpos(x::text, %L) > 0', t.tablename,
			current_setting('canary.needle')) into n;
		if n > 0 then insert into _hits values (t.tablename, n); end if;
	end loop;
end $$;
select coalesce(string_agg(tbl || '=' || n, ' ' order by tbl), 'none') from _hits;
SQL
)
	fi
	echo "#$i $out"
done
