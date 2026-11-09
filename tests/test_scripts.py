"""The packaged backup, health and admin scripts, run against stub pg_dump / pg_restore / psql / hindsight-admin
binaries in a scratch HOME. Nothing touches a database."""

import os
import shutil
import stat
import subprocess
import sys
import time
from importlib import resources
from pathlib import Path

import pytest

from omp_hindsight_guard import cli
from tests.helpers import make_setup

SCRIPTS = Path(str(resources.files("omp_hindsight_guard") / "scripts"))


def stub(path: Path, body: str) -> Path:
	path.write_text("#!/bin/sh\n" + body)
	path.chmod(0o755)
	return path


@pytest.fixture
def rig(tmp_path, scratch_home):
	bin_dir = tmp_path / "pgbin"
	bin_dir.mkdir()
	log = tmp_path / "calls.log"
	stub(
		bin_dir / "pg_dump",
		f"""echo "pg_dump $* PGPASSFILE=$PGPASSFILE" >> {log}
[ -z "$STUB_DUMP_FAIL" ] || exit 3
while [ $# -gt 0 ]; do [ "$1" = -f ] && out=$2; shift; done
if [ -n "$STUB_NO_DOCUMENTS" ]; then echo NODOCS > "$out"; else echo DUMP > "$out"; fi
""",
	)
	stub(
		bin_dir / "pg_restore",
		"""if grep -q NODOCS "$2"; then echo '; Archive'; else echo '123; 1259 1 TABLE public documents hindsight'; fi
""",
	)
	admin = stub(
		tmp_path / "admin",
		f"""echo "admin $*" >> {log}
while [ $# -gt 0 ]; do [ "$1" = -o ] && out=$2; [ "$1" = -b ] && bank=$2; shift; done
[ "$bank" != bad ] || exit 4
python3 -c 'import sys, zipfile; z = zipfile.ZipFile(sys.argv[1], "w"); z.writestr("a", "b"); z.close()' "$out"
""",
	)
	backups = tmp_path / "backups"
	env = {
		**os.environ,
		"HOME": str(scratch_home),
		"HINDSIGHT_PG_BIN": str(bin_dir),
		"HINDSIGHT_ADMIN": str(admin),
		"HINDSIGHT_BACKUP_DIR": str(backups),
		"HINDSIGHT_BANKS": "alpha beta",
		"HINDSIGHT_EXPORT_DAY": "9",  # no weekday is 9: exports only on request
	}
	return {"env": env, "backups": backups, "log": log, "bin": bin_dir}


def run_backup(rig, **extra):
	return subprocess.run(
		["bash", str(SCRIPTS / "backup.sh")],
		env={**rig["env"], **extra},
		capture_output=True,
		text=True,
		timeout=60,
		check=False,
	)


def names(directory, pattern):
	return sorted(p.name for p in directory.glob(pattern))


def test_backup_writes_a_private_verified_dump_with_the_documented_arguments(rig):
	done = run_backup(rig)
	assert done.returncode == 0, done.stderr
	(dump,) = rig["backups"].glob("hindsight-*.dump")
	assert stat.S_IMODE(rig["backups"].stat().st_mode) == 0o700 and stat.S_IMODE(dump.stat().st_mode) == 0o600
	assert f"ok: {dump.name} (5 bytes)" in done.stdout
	call = rig["log"].read_text().splitlines()[0]
	assert "-Fc -w -h 127.0.0.1 -p 5432 -U hindsight --exclude-table-data=*.llm_requests" in call
	assert call.endswith(
		"hindsight PGPASSFILE=" + str(Path(rig["env"]["HOME"]) / ".config/hindsight/.pgpass")
	)
	assert names(rig["backups"], ".*partial") == []
	assert not list(rig["backups"].glob("export-*"))  # not an export day


def test_connection_settings_come_from_the_environment(rig, tmp_path):
	done = run_backup(
		rig,
		HINDSIGHT_PG_HOST="db.example",
		HINDSIGHT_PG_PORT="6543",
		HINDSIGHT_PG_USER="svc",
		HINDSIGHT_PG_DB="memory",
		HINDSIGHT_PGPASSFILE=str(tmp_path / "pw"),
	)
	assert done.returncode == 0
	call = rig["log"].read_text().splitlines()[0]
	assert "-h db.example -p 6543 -U svc" in call and call.endswith(f"memory PGPASSFILE={tmp_path / 'pw'}")


def test_pg_binaries_come_from_path_when_no_directory_is_given(rig):
	env = {k: v for k, v in rig["env"].items() if k != "HINDSIGHT_PG_BIN"}
	env["PATH"] = f"{rig['bin']}:{env['PATH']}"
	done = subprocess.run(
		["bash", str(SCRIPTS / "backup.sh")], env=env, capture_output=True, text=True, timeout=60
	)
	assert done.returncode == 0 and list(rig["backups"].glob("hindsight-*.dump"))


def test_old_dumps_are_pruned_to_the_newest_n(rig):
	rig["backups"].mkdir(mode=0o700)
	now = time.time()
	for i in range(1, 6):
		old = rig["backups"] / f"hindsight-2020-01-0{i}-000000.dump"
		old.write_text("old")
		os.utime(old, (now - 3600 * (24 - i), now - 3600 * (24 - i)))
	done = run_backup(rig, HINDSIGHT_KEEP_DUMPS="3")
	assert done.returncode == 0
	kept = names(rig["backups"], "hindsight-*.dump")
	assert (
		len(kept) == 3
		and kept[0] == "hindsight-2020-01-04-000000.dump"
		and kept[1] == "hindsight-2020-01-05-000000.dump"
	)


def test_a_dump_without_the_documents_table_is_refused_and_old_ones_stay(rig):
	assert run_backup(rig).returncode == 0
	before = names(rig["backups"], "hindsight-*.dump")
	done = run_backup(rig, STUB_NO_DOCUMENTS="1")
	assert done.returncode == 1 and "no documents table" in done.stdout
	assert names(rig["backups"], "hindsight-*.dump") == before and names(rig["backups"], ".*partial") == []


def test_a_failing_pg_dump_fails_the_run_and_leaves_no_partial(rig):
	done = run_backup(rig, STUB_DUMP_FAIL="1")
	# nothing but the (empty, kernel-held-only) lock file: no dump, no partial file
	assert done.returncode != 0 and names(rig["backups"], "*") == [".backup.lock", ".first-run"]


def test_exports_cover_every_configured_bank_and_prune_per_bank(rig):
	rig["backups"].mkdir(mode=0o700)
	for bank in ("alpha", "beta", "gamma"):
		for i in range(3):
			f = rig["backups"] / f"export-{bank}-2020-01-0{i}-000000.zip"
			f.write_text("old")
			t = time.time() - 86400 * (10 - i)
			os.utime(f, (t, t))
	done = run_backup(rig, HINDSIGHT_EXPORT="1", HINDSIGHT_KEEP_EXPORTS="2")
	assert done.returncode == 0, done.stdout + done.stderr
	assert (
		len(names(rig["backups"], "export-alpha-*.zip")) == 2
		and len(names(rig["backups"], "export-beta-*.zip")) == 2
	)
	assert len(names(rig["backups"], "export-gamma-*.zip")) == 3  # not a configured bank: untouched
	calls = rig["log"].read_text()
	assert "admin export-bank -b alpha -o" in calls and "admin export-bank -b beta -o" in calls


def test_a_failed_export_is_logged_cleaned_up_and_fails_the_run(rig):
	done = run_backup(rig, HINDSIGHT_EXPORT="1", HINDSIGHT_BANKS="alpha bad beta")
	assert done.returncode == 1 and "fail: export-bank bad" in done.stdout
	assert names(rig["backups"], "export-bad-*") == []
	assert names(rig["backups"], "export-alpha-*") and names(
		rig["backups"], "export-beta-*"
	)  # the others ran


def test_export_on_the_configured_weekday(rig):
	weekday = time.strftime("%u")
	done = run_backup(rig, HINDSIGHT_EXPORT_DAY=weekday)
	assert done.returncode == 0 and names(rig["backups"], "export-alpha-*")
	done = run_backup(rig, HINDSIGHT_EXPORT_DAY=weekday, HINDSIGHT_BANKS="")
	assert done.returncode == 1 and "no banks" in done.stdout  # an export day with nothing to export
	done = run_backup(rig, HINDSIGHT_EXPORT_DAY=weekday, HINDSIGHT_BANKS="", HINDSIGHT_NO_EXPORT="1")
	assert done.returncode == 0  # unless exports were switched off on purpose


def test_the_cli_fills_banks_from_banks_json(rig, tmp_path, monkeypatch):
	cfg_dir = tmp_path / "cfg"
	make_setup(cfg_dir, {"one": ["~/a"], "two": ["~/b"], "three": ["~/c"]})
	for key, value in rig["env"].items():
		monkeypatch.setenv(key, value)
	monkeypatch.delenv("HINDSIGHT_BANKS")
	monkeypatch.setenv("HINDSIGHT_EXPORT", "1")
	monkeypatch.setenv("OMP_HINDSIGHT_GUARD_CONFIG_DIR", str(cfg_dir))
	assert cli.main(["backup"]) == 0
	exported = sorted({n.split("-")[1] for n in names(rig["backups"], "export-*.zip")})
	assert exported == ["one", "three", "two"]


# --- hsadmin and canary-count ------------------------------------------------------------------------------------


def test_hsadmin_runs_from_the_conf_dir_and_needs_its_env_file(tmp_path, scratch_home):
	conf = tmp_path / "conf"
	conf.mkdir()
	tool = stub(tmp_path / "hindsight-admin", 'echo "cwd=$(pwd -P) args=$*"\n')
	env = {
		**os.environ,
		"HOME": str(scratch_home),
		"HINDSIGHT_CONF_DIR": str(conf),
		"HINDSIGHT_ADMIN_BIN": str(tool),
	}
	done = subprocess.run(
		["bash", str(SCRIPTS / "hsadmin.sh"), "worker-status"], env=env, capture_output=True, text=True
	)
	assert done.returncode == 1 and ".env" in done.stderr
	(conf / ".env").write_text("X=1\n")
	done = subprocess.run(
		["bash", str(SCRIPTS / "hsadmin.sh"), "worker-status", "-v"], env=env, capture_output=True, text=True
	)
	assert done.returncode == 0 and done.stdout.strip() == f"cwd={conf.resolve()} args=worker-status -v"
	env["HINDSIGHT_CONF_DIR"] = str(tmp_path / "missing")
	done = subprocess.run(["bash", str(SCRIPTS / "hsadmin.sh")], env=env, capture_output=True, text=True)
	assert done.returncode == 1 and "HINDSIGHT_CONF_DIR" in done.stderr


def test_canary_count_wires_the_connection_and_reports_per_needle(tmp_path, scratch_home):
	log = tmp_path / "psql.log"
	bin_dir = tmp_path / "bin"
	bin_dir.mkdir()
	stub(bin_dir / "psql", f'echo "$*" >> {log}\ncat > /dev/null\necho "chunks=2"\n')
	env = {
		**os.environ,
		"HOME": str(scratch_home),
		"HINDSIGHT_PG_BIN": str(bin_dir),
		"HINDSIGHT_PG_HOST": "db",
	}
	done = subprocess.run(
		["bash", str(SCRIPTS / "canary-count.sh"), "needle one", "second"],
		env=env,
		capture_output=True,
		text=True,
	)
	assert done.returncode == 0 and done.stdout.splitlines() == ["#1 chunks=2", "#2 chunks=2"]
	first = log.read_text().splitlines()[0]
	assert "-h db -p 5432 -U hindsight -d hindsight" in first and "needle=needle one" in first
	done = subprocess.run(
		["bash", str(SCRIPTS / "canary-count.sh"), "--by-bank", "x"], env=env, capture_output=True, text=True
	)
	assert done.stdout == "#1 chunks=2\n"


# --- outbox-check -------------------------------------------------------------------------------------------------


@pytest.fixture
def outbox(tmp_path, scratch_home):
	box = tmp_path / "outbox"
	(box / "dest").mkdir(parents=True)
	box.chmod(0o700)
	(box / "dest").chmod(0o700)
	notes = tmp_path / "notes.log"
	bin_dir = tmp_path / "nbin"
	bin_dir.mkdir()
	stub(bin_dir / "osascript", f"printf '%s\\n' \"$*\" >> {notes}\n")
	stub(bin_dir / "notify-send", f"printf '%s\\n' \"$*\" >> {notes}\n")
	guard = stub(bin_dir / "guard", 'echo "unsynced=${STUB_UNSYNCED:-0}"\n')
	mnemopi = tmp_path / "mnemopi"
	mnemopi.mkdir()
	env = {
		**os.environ,
		"HOME": str(scratch_home),
		"PATH": f"{bin_dir}:/usr/bin:/bin",
		"HINDSIGHT_OUTBOX_DIR": str(box),
		"OMP_MNEMOPI_ROOT": str(mnemopi),
		"OMP_HINDSIGHT_GUARD_BIN": str(guard),
		"OMP_HINDSIGHT_GUARD_STATE_DIR": str(tmp_path / "state"),
	}
	return {"box": box, "notes": notes, "env": env, "guard": guard}


def run_outbox(o, **extra):
	return subprocess.run(
		["bash", str(SCRIPTS / "outbox-check.sh")],
		env={**o["env"], **extra},
		capture_output=True,
		text=True,
		timeout=60,
	)


def add_event(o, name, age_days=0, quarantine=False):
	folder = o["box"] / "dest" / ("quarantine" if quarantine else "")
	folder.mkdir(exist_ok=True, mode=0o700)
	path = folder / name
	path.write_text("{}")
	path.chmod(0o600)
	if age_days:
		t = time.time() - age_days * 86400
		os.utime(path, (t, t))


def test_outbox_ok_warn_and_fail_states(outbox):
	done = run_outbox(outbox)
	assert done.returncode == 0 and "ok: queued=0" in done.stdout
	add_event(outbox, "omp-1.json")
	assert "ok: queued=1" in run_outbox(outbox).stdout
	add_event(outbox, "omp-2.json", age_days=5)
	done = run_outbox(outbox)
	assert done.returncode == 0 and "warn: queued=2 stale=1" in done.stdout
	add_event(outbox, "omp-3.json", quarantine=True)
	done = run_outbox(outbox)
	assert done.returncode == 1 and "fail: quarantined=1" in done.stdout


def test_outbox_readable_by_others_fails_and_names_the_fix(outbox):
	add_event(outbox, "omp-1.json")
	(outbox["box"] / "dest").chmod(0o755)
	done = run_outbox(outbox)
	assert done.returncode == 1 and "readable by others (dirs=1" in done.stdout
	assert f"chmod -R go-rwx {outbox['box']}" in outbox["notes"].read_text()


def test_no_outbox_is_fine(outbox):
	outbox["box"].rename(outbox["box"].with_name("elsewhere"))
	done = run_outbox(outbox)
	assert done.returncode == 0 and "ok: no outbox" in done.stdout


def test_unsynced_memories_notify_once_a_day_and_never_fail(outbox):
	done = run_outbox(outbox, STUB_UNSYNCED="4")
	assert done.returncode == 0 and "ok: queued=0 unsynced=4" in done.stdout
	assert outbox["notes"].read_text().count("4 local memories") == 1
	run_outbox(outbox, STUB_UNSYNCED="4")
	assert outbox["notes"].read_text().count("4 local memories") == 1  # once per day
	state = Path(outbox["env"]["OMP_HINDSIGHT_GUARD_STATE_DIR"])
	assert stat.S_IMODE((state / "mnemopi-unsynced-notified").stat().st_mode) == 0o600
	(state / "mnemopi-unsynced-notified").write_text("1999-01-01\n")
	run_outbox(outbox, STUB_UNSYNCED="4")
	assert outbox["notes"].read_text().count("4 local memories") == 2


def test_notifications_can_be_switched_off_and_a_broken_counter_is_reported(outbox):
	run_outbox(outbox, STUB_UNSYNCED="2", OMP_HINDSIGHT_GUARD_NO_NOTIFY="1")
	assert not outbox["notes"].exists()
	outbox["guard"].write_text("#!/bin/sh\necho garbage\n")
	done = run_outbox(outbox)
	assert done.returncode == 0 and "unsynced=?" in done.stdout


@pytest.mark.skipif(sys.platform == "darwin", reason="macOS always has /usr/bin/osascript")
def test_notify_send_is_used_when_osascript_is_absent(outbox, tmp_path):
	(Path(outbox["env"]["PATH"].split(":")[0]) / "osascript").unlink()
	add_event(outbox, "omp-1.json", quarantine=True)
	done = run_outbox(outbox)
	assert done.returncode == 1 and "memory outbox" in outbox["notes"].read_text()


# --- review fixes: M1, L8, L9 ----------------------------------------------------------------------------------


def test_pruning_one_bank_never_touches_a_bank_whose_name_extends_it(rig):
	"""M1: export-a-*.zip also matched export-a-b-*.zip, so two banks shared one keep budget."""
	rig["backups"].mkdir(mode=0o700)
	now = time.time()
	for bank in ("a", "a-b"):
		for i in range(3):
			f = rig["backups"] / f"export-{bank}-2020-01-0{i + 1}-000000.zip"
			f.write_text("old")
			os.utime(f, (now - 86400 * (10 - i), now - 86400 * (10 - i)))
	done = run_backup(rig, HINDSIGHT_EXPORT="1", HINDSIGHT_BANKS="a a-b", HINDSIGHT_KEEP_EXPORTS="2")
	assert done.returncode == 0, done.stdout + done.stderr
	stamps = {bank: names(rig["backups"], f"export-{bank}-2*.zip") for bank in ("a", "a-b")}
	assert len(stamps["a"]) == 2 and len(stamps["a-b"]) == 2, stamps
	assert "export-a-b-2020-01-01-000000.zip" not in stamps["a-b"]  # the oldest of its own bank went
	assert "export-a-b-2020-01-03-000000.zip" in stamps["a-b"]


def test_a_binary_hindsight_admin_is_run_directly(rig, tmp_path):
	"""L9(b): HINDSIGHT_ADMIN was run as `bash "$admin"`, which cannot run a binary or a python script."""
	admin = tmp_path / "admin-py"
	admin.write_text(
		"#!/usr/bin/env python3\nimport sys\nout = sys.argv[sys.argv.index('-o') + 1]\nimport zipfile; z = zipfile.ZipFile(out, 'w'); z.writestr('a', 'b'); z.close()\n"
	)
	admin.chmod(0o755)
	done = run_backup(rig, HINDSIGHT_EXPORT="1", HINDSIGHT_ADMIN=str(admin))
	assert done.returncode == 0, done.stdout + done.stderr
	assert names(rig["backups"], "export-alpha-*.zip")


def test_a_large_table_of_contents_does_not_discard_a_good_dump(rig):
	"""L9(a): grep -q exits early; under pipefail the writer's SIGPIPE made the check fail."""
	stub(
		rig["bin"] / "pg_restore",
		"echo '123; 1259 1 TABLE public documents hindsight'\nyes ';  junk table of contents line' | head -c 6000000\n",
	)
	done = run_backup(rig)
	assert done.returncode == 0, done.stdout + done.stderr
	assert names(rig["backups"], "hindsight-*.dump")


def test_a_backup_dir_holding_other_files_is_refused_and_left_alone(rig):
	"""L9(c): HINDSIGHT_BACKUP_DIR=$HOME must never be chmod'd."""
	rig["backups"].mkdir(mode=0o755)
	rig["backups"].chmod(0o755)
	(rig["backups"] / "notes.txt").write_text("x")
	done = run_backup(rig)
	assert done.returncode == 1 and "not a backup directory" in (done.stdout + done.stderr)
	assert stat.S_IMODE(rig["backups"].stat().st_mode) == 0o755
	assert [p.name for p in rig["backups"].iterdir()] == ["notes.txt"]


def test_notification_text_is_escaped_for_applescript(outbox):
	"""L8: a quote or backslash in the outbox path must not break out of the AppleScript string."""
	weird = outbox["box"].with_name('box"q\\z')
	outbox["box"].rename(weird)
	add_event(outbox | {"box": weird}, "omp-1.json", quarantine=True)
	(weird / "dest").chmod(0o755)
	done = run_outbox(outbox, HINDSIGHT_OUTBOX_DIR=str(weird))
	assert done.returncode == 1
	text = outbox["notes"].read_text()
	assert 'box\\"q\\\\z' in text and 'box"q' not in text.replace('box\\"q', "")


@pytest.mark.parametrize("bits", [0o720, 0o710, 0o602, 0o601])
def test_any_group_or_other_access_to_the_outbox_fails(outbox, bits):
	"""L8: only read bits were tested; write and execute bits passed."""
	add_event(outbox, "omp-1.json")
	(outbox["box"] / "dest" / "omp-1.json").chmod(bits)
	done = run_outbox(outbox)
	assert done.returncode == 1 and "readable by others" in done.stdout, done.stdout


# --- second review: 13 (backup races, validation), 14 (output directory), 15 (outbox false health) -------------------


def test_f13_two_backups_cannot_run_at_once(rig):
	stub(
		rig["bin"] / "pg_dump",
		f"""echo "pg_dump" >> {rig["log"]}
sleep 3
while [ $# -gt 0 ]; do [ "$1" = -f ] && out=$2; shift; done
echo DUMP > "$out"
""",
	)
	first = subprocess.Popen(
		["bash", str(SCRIPTS / "backup.sh")],
		env=rig["env"],
		stdout=subprocess.PIPE,
		stderr=subprocess.PIPE,
		text=True,
	)
	try:
		deadline = time.time() + 10
		while time.time() < deadline and not rig["log"].exists():
			time.sleep(0.05)
		second = run_backup(rig)
		assert second.returncode == 1 and "another backup" in (second.stdout + second.stderr)
	finally:
		first.communicate(timeout=30)
	assert first.returncode == 0
	assert len(names(rig["backups"], "hindsight-*.dump")) == 1
	assert (
		run_backup(rig).returncode == 0
	)  # the lock died with the first run: nothing to clean up, nothing stale


def test_f13_an_export_that_is_not_a_valid_archive_is_never_kept(rig, tmp_path):
	admin = stub(
		tmp_path / "admin-bad",
		'while [ $# -gt 0 ]; do [ "$1" = -o ] && out=$2; shift; done\necho junk > "$out"\n',
	)
	done = run_backup(rig, HINDSIGHT_EXPORT="1", HINDSIGHT_ADMIN=str(admin))
	assert done.returncode == 1 and "not a valid archive" in done.stdout
	assert names(rig["backups"], "export-*") == [] and names(rig["backups"], ".export-*") == []


def test_f13_exports_are_written_aside_and_renamed(rig, tmp_path):
	"""While an export runs, the final name does not exist yet (doctor's age check would trust a partial file)."""
	seen = tmp_path / "seen"
	admin = stub(
		tmp_path / "admin-watch",
		f"""while [ $# -gt 0 ]; do [ "$1" = -o ] && out=$2; shift; done
ls "{rig["backups"]}" > "{seen}"
python3 -c 'import sys, zipfile; z = zipfile.ZipFile(sys.argv[1], "w"); z.writestr("a", "b"); z.close()' "$out"
""",
	)
	done = run_backup(rig, HINDSIGHT_EXPORT="1", HINDSIGHT_ADMIN=str(admin), HINDSIGHT_BANKS="alpha")
	assert done.returncode == 0
	assert not any(n.startswith("export-alpha") for n in seen.read_text().split())
	assert names(rig["backups"], "export-alpha-*.zip") and names(rig["backups"], ".export-*") == []


@pytest.mark.parametrize("bad", ["0", "-1", "abc", "", "1.5", "3 4"])
def test_f13_retention_counts_must_be_positive_integers(rig, bad):
	rig["backups"].mkdir(mode=0o700)
	old = rig["backups"] / "hindsight-2020-01-01-000000.dump"
	old.write_text("old")
	for var in ("HINDSIGHT_KEEP_DUMPS", "HINDSIGHT_KEEP_EXPORTS"):
		done = run_backup(rig, **{var: bad})
		assert done.returncode == 2 and var in done.stderr, (var, bad, done.stdout, done.stderr)
		assert old.exists() and names(rig["backups"], "hindsight-*.dump") == [old.name]


def test_f14_a_symlinked_backup_directory_is_refused(rig, tmp_path):
	target = tmp_path / "unrelated"
	target.mkdir(mode=0o755)
	target.chmod(0o755)
	(target / "notes.txt").write_text("x")
	rig["backups"].symlink_to(target)
	done = run_backup(rig)
	assert done.returncode == 1 and "symlink" in (done.stdout + done.stderr)
	assert stat.S_IMODE(target.stat().st_mode) == 0o755 and [p.name for p in target.iterdir()] == [
		"notes.txt"
	]


def test_f15_a_symlinked_outbox_is_refused_not_reported_healthy(outbox, tmp_path):
	add_event(outbox, "omp-1.json", quarantine=True)
	link = tmp_path / "outbox-link"
	link.symlink_to(outbox["box"])
	done = run_outbox(outbox, HINDSIGHT_OUTBOX_DIR=str(link))
	assert done.returncode == 1 and "symlink" in done.stdout and "ok:" not in done.stdout


def test_f15_a_symlink_inside_the_outbox_is_refused(outbox, tmp_path):
	elsewhere = tmp_path / "elsewhere"
	elsewhere.mkdir(mode=0o700)
	(elsewhere / "omp-9.json").write_text("{}")
	(outbox["box"] / "linked").symlink_to(elsewhere)
	done = run_outbox(outbox)
	assert done.returncode == 1 and "symlink" in done.stdout


def test_f15_staleness_is_exactly_three_days(outbox):
	add_event(outbox, "omp-1.json", age_days=2.9)
	assert "ok: queued=1" in run_outbox(outbox).stdout
	add_event(outbox, "omp-2.json", age_days=3.1)
	done = run_outbox(outbox)
	assert done.returncode == 0 and "warn: queued=2 stale=1" in done.stdout


def test_f15_the_header_says_what_the_script_does():
	text = (SCRIPTS / "outbox-check.sh").read_text()
	assert "never reads the events or the memories" not in text
	assert "stale events are a warning (exit 0)" in text


# --- third review: the lock (R4), exact pruning (R6), bounded retention (R7), real archive checks (R8) ----------------


def slow_dump(rig, seconds):
	stub(
		rig["bin"] / "pg_dump",
		f"""echo "pg_dump" >> {rig["log"]}
sleep {seconds}
while [ $# -gt 0 ]; do [ "$1" = -f ] && out=$2; shift; done
echo DUMP > "$out"
""",
	)


def test_r4_only_one_of_many_simultaneous_backups_runs(rig):
	"""The old lock directory was empty for an instant after mkdir, and a second run took that for a stale lock."""
	slow_dump(rig, 2)
	procs = [
		subprocess.Popen(
			["bash", str(SCRIPTS / "backup.sh")],
			env=rig["env"],
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE,
			text=True,
		)
		for _ in range(8)
	]
	codes = []
	for proc in procs:
		proc.communicate(timeout=60)
		codes.append(proc.returncode)
	assert sorted(codes) == [0] + [1] * 7
	assert len(rig["log"].read_text().splitlines()) == 1  # pg_dump ran once
	assert len(names(rig["backups"], "hindsight-*.dump")) == 1


def test_r4_a_killed_run_leaves_a_lock_that_the_kernel_releases(rig):
	slow_dump(rig, 2)
	first = subprocess.Popen(
		["bash", str(SCRIPTS / "backup.sh")], env=rig["env"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
	)
	deadline = time.time() + 10
	while time.time() < deadline and not rig["log"].exists():
		time.sleep(0.05)
	first.kill()
	first.communicate()
	time.sleep(2.5)  # the orphaned dump (it inherited the lock) finishes
	for _ in range(2):
		done = run_backup(rig, HINDSIGHT_EXPORT_DAY="9")
		assert done.returncode == 0, done.stderr


def test_r4_a_lock_file_left_by_a_dead_run_blocks_nothing_and_a_directory_from_an_old_version_is_explained(
	rig,
):
	rig["backups"].mkdir(mode=0o700)
	(rig["backups"] / ".backup.lock").write_text("12345\n")  # no process holds it
	assert run_backup(rig).returncode == 0
	(rig["backups"] / ".backup.lock").unlink()
	(rig["backups"] / ".backup.lock").mkdir()  # what the first release of the script left behind
	done = run_backup(rig)
	assert done.returncode == 1 and "directory left by an older version" in done.stderr


def test_r4_the_lock_file_is_private_and_is_never_a_symlink_target(rig, tmp_path):
	rig["backups"].mkdir(mode=0o700)
	victim = tmp_path / "victim"
	victim.write_text("keep")
	(rig["backups"] / ".backup.lock").symlink_to(victim)
	done = run_backup(rig)
	assert done.returncode == 1 and victim.read_text() == "keep"


def test_r6_a_bank_never_prunes_the_exports_of_another_bank_whose_name_extends_it(rig):
	rig["backups"].mkdir(mode=0o700)
	other = rig["backups"] / "export-a-2026-11-09-123456-2026-01-01-000000.zip"  # bank "a-2026-11-09-123456"
	other.write_text("x")
	mine_old = rig["backups"] / "export-a-2026-01-02-000000.zip"
	mine_old.write_text("x")
	mine_older = rig["backups"] / "export-a-2026-01-03-000000.zip"
	mine_older.write_text("x")
	for offset, path in enumerate((other, mine_old, mine_older)):
		stamp = time.time() - 1000000 + offset * 1000  # the other bank's file is the oldest of all
		os.utime(path, (stamp, stamp))
	done = run_backup(rig, HINDSIGHT_EXPORT="1", HINDSIGHT_BANKS="a", HINDSIGHT_KEEP_EXPORTS="2")
	assert done.returncode == 0, done.stdout
	assert other.exists()  # not counted in bank a's budget
	assert not mine_old.exists() and mine_older.exists() and names(rig["backups"], "export-a-2026-11*")


@pytest.mark.parametrize("big", ["10000", "9223372036854775808", "99999999999999999999999", "0009"])
def test_r7_retention_counts_beyond_the_documented_range_are_rejected_before_anything_is_deleted(rig, big):
	rig["backups"].mkdir(mode=0o700)
	old = rig["backups"] / "hindsight-2020-01-01-000000.dump"
	old.write_text("old")
	for var in ("HINDSIGHT_KEEP_DUMPS", "HINDSIGHT_KEEP_EXPORTS"):
		done = run_backup(rig, **{var: big})
		assert done.returncode == 2 and var in done.stderr and "1 to 9999" in done.stderr
		assert old.exists() and names(rig["backups"], "hindsight-*.dump") == [old.name]


def test_r7_the_largest_accepted_count_keeps_the_new_dump(rig):
	rig["backups"].mkdir(mode=0o700)
	done = run_backup(rig, HINDSIGHT_KEEP_DUMPS="9999")
	assert done.returncode == 0 and len(names(rig["backups"], "hindsight-*.dump")) == 1


def test_r8_a_truncated_archive_is_never_promoted_and_older_exports_survive(rig, tmp_path):
	rig["backups"].mkdir(mode=0o700)
	older = rig["backups"] / "export-alpha-2026-01-01-000000.zip"
	older.write_text("previous good export")
	admin = stub(
		tmp_path / "admin-truncated",
		"""while [ $# -gt 0 ]; do [ "$1" = -o ] && out=$2; shift; done
python3 - "$out" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("bank.json", "x" * 5000)
data = open(sys.argv[1], "rb").read()
open(sys.argv[1], "wb").write(data[: len(data) // 2])
PY
""",
	)
	done = run_backup(
		rig,
		HINDSIGHT_EXPORT="1",
		HINDSIGHT_ADMIN=str(admin),
		HINDSIGHT_BANKS="alpha",
		HINDSIGHT_KEEP_EXPORTS="1",
	)
	assert done.returncode == 1 and "not a valid archive" in done.stdout
	assert older.exists() and names(rig["backups"], "export-alpha-2026-0[2-9]*") == []
	assert [n for n in names(rig["backups"], "export-alpha-*") if n != older.name] == []


def test_r8_the_check_does_not_depend_on_unzip_being_installed(rig, tmp_path):
	"""PATH without unzip: the check is Python's, so a junk file starting with PK still fails."""
	admin = stub(
		tmp_path / "admin-pk",
		'while [ $# -gt 0 ]; do [ "$1" = -o ] && out=$2; shift; done\nprintf PKjunk > "$out"\n',
	)
	bare = tmp_path / "bare-bin"
	bare.mkdir()
	for tool in (
		"bash",
		"date",
		"mktemp",
		"find",
		"head",
		"ls",
		"rm",
		"mv",
		"chmod",
		"mkdir",
		"stat",
		"grep",
		"cat",
		"dirname",
	):
		found = shutil.which(tool)
		if found:
			(bare / tool).symlink_to(found)
	for fake in ("pg_dump", "pg_restore"):
		(bare / fake).symlink_to(rig["bin"] / fake)
	done = run_backup(
		rig,
		HINDSIGHT_EXPORT="1",
		HINDSIGHT_ADMIN=str(admin),
		HINDSIGHT_BANKS="alpha",
		PATH=str(bare),
		HINDSIGHT_PYTHON=sys.executable,
		HINDSIGHT_PG_BIN="",
	)
	assert done.returncode == 1 and "not a valid archive" in done.stdout


def test_f16_no_banks_fails_every_run_not_only_on_export_days(rig):
	done = run_backup(rig, HINDSIGHT_BANKS="")  # export day is "9": never
	assert done.returncode == 1 and "no banks configured" in done.stdout
	assert names(rig["backups"], "hindsight-*.dump")  # the dump itself was still made
	assert run_backup(rig, HINDSIGHT_BANKS="", HINDSIGHT_NO_EXPORT="1").returncode == 0


# --- third review: the outbox check's state file (R12) ---------------------------------------------------------------


def test_r12_the_outbox_check_does_not_write_through_a_symlinked_state_directory(outbox, tmp_path):
	victim = tmp_path / "victim"
	victim.mkdir()
	link = tmp_path / "state-link"
	link.symlink_to(victim)
	done = run_outbox(outbox, STUB_UNSYNCED="3", OMP_HINDSIGHT_GUARD_STATE_DIR=str(link))
	assert done.returncode == 0 and "unsynced=3" in done.stdout
	assert list(victim.iterdir()) == []


def test_r12_the_outbox_check_replaces_a_symlinked_notice_file_instead_of_following_it(outbox, tmp_path):
	state = tmp_path / "state"
	state.mkdir(mode=0o700)
	victim = tmp_path / "victim.txt"
	victim.write_text("precious\n")
	(state / "mnemopi-unsynced-notified").symlink_to(victim)
	run_outbox(outbox, STUB_UNSYNCED="3", OMP_HINDSIGHT_GUARD_STATE_DIR=str(state))
	assert victim.read_text() == "precious\n"


# --- second verification pass: N7 (a failed export prunes nothing), N9 (the first-run record) ---------------------


def test_n7_a_failed_export_never_prunes_older_exports(rig, tmp_path):
	rig["backups"].mkdir(mode=0o700)
	older = []
	for day in (1, 2, 3):
		path = rig["backups"] / f"export-alpha-2026-01-0{day}-000000.zip"
		path.write_text("previous good export")
		older.append(path)
	admin = stub(
		tmp_path / "admin-junk",
		'while [ $# -gt 0 ]; do [ "$1" = -o ] && out=$2; shift; done\necho junk > "$out"\n',
	)
	done = run_backup(
		rig,
		HINDSIGHT_EXPORT="1",
		HINDSIGHT_ADMIN=str(admin),
		HINDSIGHT_BANKS="alpha",
		HINDSIGHT_KEEP_EXPORTS="1",
	)
	assert done.returncode == 1
	assert all(path.exists() for path in older)  # retention was reduced to 1, yet nothing was deleted
	done = run_backup(rig, HINDSIGHT_EXPORT="1", HINDSIGHT_BANKS="alpha", HINDSIGHT_KEEP_EXPORTS="1")
	assert done.returncode == 0 and len(names(rig["backups"], "export-alpha-*")) == 1  # a good one prunes


def test_n9_backup_records_when_it_began_once_and_never_rewrites_it(rig):
	assert run_backup(rig).returncode == 0
	first = (rig["backups"] / ".first-run").read_text()
	assert first.strip().isdigit()
	time.sleep(1.1)
	assert run_backup(rig).returncode == 0
	assert (rig["backups"] / ".first-run").read_text() == first
