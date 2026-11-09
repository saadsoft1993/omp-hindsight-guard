# ruff: noqa: F811
"""Fourth verification pass: ACLs (V1), lossless symlink targets (V2), backup ancestry (V3), unambiguous source
identity (V4), exact working directories (V5), symlinks that contain `..` (V6), exact routing rows (V7). Each failed
before its fix."""

import os
import re
import shutil
import subprocess
import sys

import pytest

from omp_hindsight_guard import config as cfg
from omp_hindsight_guard import importer as im
from omp_hindsight_guard import trustwalk
from tests.helpers import make_setup
from tests.test_hook import overlay_args
from tests.test_importer import dry_digest, row, run_main, write_overlays
from tests.test_importer import world as import_world  # noqa: F401
from tests.test_review3_hooks import BLOCK, launch, run, runner, world  # noqa: F401
from tests.test_scripts import rig, run_backup  # noqa: F401

CHMOD = "/bin/chmod"
DARWIN = sys.platform == "darwin"
SETFACL = shutil.which("setfacl")
needs_acl = pytest.mark.skipif(not (DARWIN or SETFACL), reason="no ACL tool on this platform")


def grant(path, what):
	"""Give everybody `what` ('read' or 'write') on `path` through an ACL, leaving the mode bits alone."""
	if DARWIN:
		subprocess.run([CHMOD, "+a", f"everyone allow {what}", str(path)], check=True)
	else:
		perm = "r" if what == "read" else "w"
		subprocess.run([SETFACL, "-m", f"u:nobody:{perm}", str(path)], check=True)


# --- V1: an ACL is as good as a mode bit ---------------------------------------------------------------------------


@needs_acl
def test_v1_an_acl_that_lets_others_write_banks_json_makes_the_loader_refuse(tmp_path):
	cfg_dir = tmp_path / "cfg"
	config = make_setup(cfg_dir, {"alpha": ["~/a"]})
	assert cfg.load_config(config.path)  # fine as it is
	grant(config.path, "write")
	with pytest.raises(cfg.ConfigError, match="ACL"):
		cfg.load_config(config.path)


@needs_acl
def test_v1_an_acl_that_lets_others_read_a_key_file_is_refused(tmp_path):
	key = tmp_path / "k.key"
	key.write_text("k" * 40)
	key.chmod(0o600)
	assert cfg.read_key(key, "t") == "k" * 40
	grant(key, "read")
	with pytest.raises(cfg.ConfigError, match="ACL"):
		cfg.read_key(key, "t")


@needs_acl
def test_v1_a_directory_with_a_write_acl_is_untrusted_for_every_path_below_it(tmp_path):
	private = tmp_path / "private"
	private.mkdir(mode=0o700)
	(private / "f").write_text("x")
	grant(private, "write")
	with pytest.raises(trustwalk.TrustError, match="ACL"):
		trustwalk.check_path(private / "f")


@pytest.mark.skipif(not DARWIN, reason="deny entries are a macOS ACL notion")
def test_v1_a_deny_only_acl_is_harmless(tmp_path):
	path = tmp_path / "f"
	path.write_text("x")
	path.chmod(0o600)
	subprocess.run([CHMOD, "+a", "everyone deny write", str(path)], check=True)
	trustwalk.check_path(path, secret=True)


@needs_acl
def test_v1_the_launcher_ignores_an_overlay_that_an_acl_makes_writable(runner, world):
	grant(world["overlays"] / "beta.yml", "write")
	proc, _ = launch(runner, world, world["home"] / "work/beta-site")
	assert "ACL" in proc.stderr and proc.stdout.splitlines()[0] == "argv:"
	proc, _ = launch(runner, world, world["home"] / "work/beta-site", extra=BLOCK, check=False)
	assert proc.returncode == 75 and proc.stdout == ""


def test_v1_linux_acl_entries_are_read_from_the_posix_acl_attribute(monkeypatch, tmp_path):
	import struct

	def entries(*items):
		return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *item) for item in items)

	path = tmp_path / "f"
	path.write_text("x")
	owner = os.lstat(path).st_uid
	monkeypatch.setattr(
		os, "listxattr", lambda p, follow_symlinks=True: ["system.posix_acl_access"], raising=False
	)
	base = [(0x01, 6, 0xFFFFFFFF), (0x04, 0, 0xFFFFFFFF), (0x20, 0, 0xFFFFFFFF)]
	for items, secret, bad in (
		([*base, (0x02, 2, 12345), (0x10, 7, 0xFFFFFFFF)], False, True),  # another user may write
		([*base, (0x08, 2, 12345)], False, True),  # a group may write
		([*base, (0x02, 4, 12345)], False, False),  # read only, not a secret
		([*base, (0x02, 4, 12345)], True, True),  # read, and it is a secret
		([*base, (0x02, 6, owner)], True, False),  # the owner's own named entry
	):
		monkeypatch.setattr(
			os, "getxattr", lambda p, n, follow_symlinks=True, items=items: entries(*items), raising=False
		)
		problem = trustwalk._acl_linux(str(path), secret)
		assert (problem is not None) == bad, items


# --- V2: a symlink target is validated exactly as it will be used ----------------------------------------------------


def test_v2_a_target_ending_in_a_newline_is_not_validated_as_a_different_directory(tmp_path):
	trusted_decoy = tmp_path / "safe"
	trusted_decoy.mkdir(mode=0o700)
	evil = tmp_path / "safe\n"  # a different directory whose name ends with a newline
	evil.mkdir()
	evil.chmod(0o777)
	link = tmp_path / "cfg"
	os.symlink(str(evil), link)
	with pytest.raises(trustwalk.TrustError, match="writable by group or other"):
		trustwalk.check_path(link / "overlays")


def test_v2_launchers_refuse_configuration_behind_a_newline_ended_symlink_target(runner, world, tmp_path):
	decoy = tmp_path / "decoy"  # what a lossy read of the link would have validated
	decoy.mkdir(mode=0o700)
	evil = tmp_path / "decoy\n"
	evil.mkdir()
	evil.chmod(0o777)
	for name in ("routes.tsv", "alpha.yml", "beta.yml"):
		shutil.copy(world["overlays"] / name, evil / name)
		shutil.copy(world["overlays"] / name, decoy / name)
	link = tmp_path / "cfglink"
	os.symlink(str(evil), link)
	extra = {"OMP_HINDSIGHT_GUARD_OVERLAY_DIR": str(link)}
	proc, _ = launch(runner, world, world["home"] / "work/beta-site", extra=extra)
	assert "not in a trusted location" in proc.stderr and proc.stdout.splitlines()[0] == "argv:"


# --- V3: the backup directory's ancestry ----------------------------------------------------------------------------


def test_v3_backup_refuses_a_directory_below_a_replaceable_ancestor(rig, tmp_path):
	shared = tmp_path / "shared"
	shared.mkdir()
	shared.chmod(0o777)  # not sticky: anybody could rename what is below
	target = shared / "backups"
	done = run_backup(rig, HINDSIGHT_BACKUP_DIR=str(target))
	assert done.returncode == 1 and "not in a trusted location" in done.stderr
	assert not target.exists()  # nothing was created, nothing dumped
	assert not rig["log"].exists()


def test_v3_backup_follows_a_trusted_symlinked_ancestor_and_still_works(rig, tmp_path):
	real = tmp_path / "real"
	real.mkdir(mode=0o700)
	link = tmp_path / "link"
	link.symlink_to(real)
	done = run_backup(rig, HINDSIGHT_BACKUP_DIR=str(link / "backups"))
	assert done.returncode == 0, done.stderr


# --- V4: an identity that reads one way ------------------------------------------------------------------------------


def test_v4_the_reported_pair_of_distinct_sources_no_longer_shares_an_id_or_a_source_key():
	a = row("proj:w:7", "working_memory", "8", "alpha", "project:a", "first")
	b = row("proj", "working_memory", "7:w:8", "alpha", "project:a", "second")
	assert im.default_document_id(a) != im.default_document_id(b)
	assert a.source_key != b.source_key
	assert re.fullmatch(r".*@h[0-9a-f]{64}", im.default_document_id(a))  # the whole SHA-256, not a prefix
	ledger = im.Ledger()
	docs = im.dedupe([a])
	im.apply_ledger(docs, ledger)
	im.record(ledger, docs)
	later = im.dedupe([b])
	assert im.apply_ledger(later, ledger) == [] and im.doc_id_of(later[0]) not in ledger.documents


def test_v4_a_plain_identity_keeps_its_readable_id_and_key():
	plain = row("pilot-k2j3", "working_memory", "p1", "alpha", "project:a", "x")
	assert (
		im.default_document_id(plain) == "mnemopi:alpha:pilot-k2j3:w:p1"
		and plain.source_key == "pilot-k2j3:w:p1"
	)


def test_v4_a_hashed_source_key_can_never_equal_a_plain_one():
	hashed = row("a:b", "working_memory", "1", "alpha", "project:a", "x").source_key
	assert hashed.startswith("@") and hashed.count(":") == 0  # every plain key has two colons


def test_v4_a_ledger_belongs_to_one_mnemopi_root(import_world, tmp_path):
	from tests.test_importer import FakeOpener

	write_overlays(import_world["overlays"])
	assert (
		run_main(import_world, "--send", "--confirm", dry_digest(import_world), opener=FakeOpener())[0] == 0
	)
	other = tmp_path / "other-store"
	other.mkdir()
	code, text = run_main(import_world, "--root", str(other))
	assert code == im.EXIT_LEDGER and "belongs to another mnemopi root" in text


# --- V5, V7: the working directory is exact; a routing row is exact ----------------------------------------------------


def test_v5_a_directory_whose_name_ends_in_a_newline_is_not_the_root(runner, world):
	home = world["home"]
	root = home / "work/proj"
	(root / "sub").mkdir(parents=True)
	sibling = home / "work/proj\n"
	(sibling / "sub").mkdir(parents=True)
	world["routes"].write_text("alpha\t~/work/proj\n")
	assert run(runner, world, root / "sub")[0] == overlay_args(world, "alpha")
	assert (
		run(runner, world, sibling / "sub")[0] == "argv:"
	)  # a different folder, not `proj` with its newline trimmed


@pytest.mark.parametrize("locale", ["tr_TR.UTF-8", "en_US.UTF-8", "de_DE.UTF-8"])
def test_v5_the_answer_does_not_depend_on_the_locale(runner, world, locale):
	home = world["home"]
	(home / "work/Index-App/sub").mkdir(parents=True)
	world["routes"].write_text("alpha\t~/work/INDEX-app\n")
	for env in ({"LC_ALL": locale}, {"LANG": locale, "LC_CTYPE": locale}):
		argv, _ = run(runner, world, home / "work/Index-App/sub", extra=env)
		assert argv == overlay_args(world, "alpha")


@pytest.mark.parametrize(
	"line",
	[
		"alpha\t\t~/work/alpha-app",  # an empty middle column: read would have collapsed it
		"alpha\t~/work/alpha-app\r",  # a CRLF table
		"\talpha\t~/work/alpha-app",
		"alpha ~/work/alpha-app",  # spaces, no tab
	],
)
def test_v7_a_routing_row_must_have_exactly_one_tab_between_two_fields(runner, world, line):
	world["routes"].write_text(f"beta\t~/work/beta-site\n{line}\n")
	proc, _ = launch(runner, world, world["home"] / "work/alpha-app/ui", extra=BLOCK, check=False)
	assert proc.returncode == 75 and proc.stdout == "" and "malformed entry" in proc.stderr, repr(line)


def test_v7_an_unreadable_routing_table_is_unknown_configuration_not_an_empty_one(runner, world):
	world["routes"].unlink()
	world["routes"].mkdir()  # exists, cannot be read as a file
	proc, _ = launch(runner, world, world["home"] / "work/alpha-app/ui", extra=BLOCK, check=False)
	assert proc.returncode == 75 and "missing or unreadable" in proc.stderr


def test_v7_a_table_that_is_not_utf8_is_malformed(runner, world):
	world["routes"].write_bytes(b"beta\t~/work/beta-site\nalpha\t~/work/\xff\xfe\n")
	proc, _ = launch(runner, world, world["home"] / "work/beta-site", extra=BLOCK, check=False)
	assert proc.returncode == 75 and "malformed entry" in proc.stderr


# --- V6: a safe relative symlink is resolved, not rejected -------------------------------------------------------------


def test_v6_a_relative_symlink_with_dot_dot_is_accepted_by_every_launcher(runner, world, tmp_path):
	base = tmp_path / "base"
	(base / "dotfiles").mkdir(parents=True)
	(base / "home").mkdir()
	os.rename(world["overlays"], base / "dotfiles" / "config")
	(base / "home" / ".cfg").symlink_to("../dotfiles/config")
	extra = {"OMP_HINDSIGHT_GUARD_OVERLAY_DIR": str(base / "home" / ".cfg")}
	proc, _ = launch(runner, world, world["home"] / "work/beta-site", extra=extra)
	assert "not in a trusted location" not in proc.stderr
	assert proc.stdout.splitlines()[0] == f"argv: [--config] [{base / 'home' / '.cfg' / 'beta.yml'}]"


def test_v6_a_chain_of_many_links_is_followed_up_to_the_kernels_own_limit(tmp_path):
	target = tmp_path / "real"
	target.mkdir(mode=0o700)
	previous = target
	for i in range(
		30
	):  # more than the twelve the shell walk allowed, fewer than the forty it shares with Python
		link = tmp_path / f"l{i}"
		link.symlink_to(previous)
		previous = link
	trustwalk.check_path(previous)
	loop = tmp_path / "loop"
	loop.symlink_to(loop)
	with pytest.raises(trustwalk.TrustError):
		trustwalk.check_path(loop / "x")


# --- the helper is a dependency of the launchers: its absence is "cannot tell", never "trusted" -----------------------


def without_helper(runner, world):
	from pathlib import Path

	from tests.test_hook import environment

	return environment(world, runner)["PATH"].replace(f"{Path(sys.executable).parent}:", "")


def test_the_launchers_run_unchanged_with_a_notice_when_the_helper_is_missing_and_refuse_under_block(
	runner, world
):
	extra = {"PATH": without_helper(runner, world)}
	proc, _ = launch(runner, world, world["home"] / "work/beta-site", extra=extra)
	assert (
		proc.stdout.splitlines()[0] == "argv:" and "omp-hindsight-guard-pick is not available" in proc.stderr
	)
	proc, _ = launch(runner, world, world["home"] / "work/beta-site", extra={**extra, **BLOCK}, check=False)
	assert proc.returncode == 75 and proc.stdout == "" and "refusing to start" in proc.stderr
