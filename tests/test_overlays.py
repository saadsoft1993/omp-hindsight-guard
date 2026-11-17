import stat

import pytest
import yaml

from omp_hindsight_guard import overlays
from omp_hindsight_guard.config import load_keys
from tests.helpers import make_setup

BANKS = {
	"alpha": ["~/work/alpha-app", "~/work/tools"],
	"beta": ["~/work/beta-site"],
	"gamma": ["/srv/gamma"],
}


@pytest.fixture
def setup(tmp_path):
	config = make_setup(tmp_path / "cfg", BANKS)
	return config, tmp_path / "overlays"


def mode(path):
	return stat.S_IMODE(path.stat().st_mode)


def test_one_overlay_per_bank_plus_routes_all_private(setup):
	config, out = setup
	written = overlays.write_overlays(config, out)
	assert sorted(p.name for p in written) == ["alpha.yml", "beta.yml", "gamma.yml", "routes.tsv"]
	assert mode(out) == 0o700
	assert all(mode(p) == 0o600 for p in written)
	keys = load_keys(config)
	for name in BANKS:
		data = yaml.safe_load((out / f"{name}.yml").read_text())
		assert data["memory"] == {"backend": "hindsight"}
		h = data["hindsight"]
		assert h["apiUrl"] == "http://127.0.0.1:8888" and h["bankId"] == name
		assert h["apiToken"] == keys.banks[name]
		assert h["scoping"] == "per-project-tagged" and h["globalScope"] is False
	assert (out / "routes.tsv").read_text() == (
		"alpha\t~/work/alpha-app\nalpha\t~/work/tools\nbeta\t~/work/beta-site\ngamma\t/srv/gamma\n"
	)


def test_the_url_is_an_argument(setup):
	config, out = setup
	overlays.write_overlays(config, out, "https://memory.example:8898/")
	assert (
		yaml.safe_load((out / "beta.yml").read_text())["hindsight"]["apiUrl"] == "https://memory.example:8898"
	)
	overlays.write_overlays(config, out, "http://localhost:9000")
	assert yaml.safe_load((out / "beta.yml").read_text())["hindsight"]["apiUrl"] == "http://localhost:9000"


def test_overlay_timeouts_suit_a_remote_server(setup):
	config, out = setup
	overlays.write_overlays(config, out, "https://memory.example:8898")
	lines = (out / "alpha.yml").read_text().splitlines(keepends=True)
	for line in ("  recallTimeoutMs: 8000\n", "  requestTimeoutMs: 15000\n", "  retainTimeoutMs: 15000\n"):
		assert line in lines


@pytest.mark.parametrize(
	"url",
	["http://memory.example:8898", "ftp://x", "memory.example", "http://", "https://", "file:///etc/passwd"],
)
def test_a_url_that_would_expose_the_key_is_refused(setup, url):
	config, out = setup
	with pytest.raises(ValueError, match="apiUrl"):
		overlays.write_overlays(config, out, url)
	assert not out.exists()


def test_the_default_url_follows_the_proxy_settings(tmp_path):
	config = make_setup(tmp_path / "cfg", BANKS, listen_port=9911)
	overlays.write_overlays(config, tmp_path / "o")
	assert (
		yaml.safe_load((tmp_path / "o/alpha.yml").read_text())["hindsight"]["apiUrl"]
		== "http://127.0.0.1:9911"
	)


def test_rewriting_replaces_files_atomically_and_keeps_modes(setup):
	config, out = setup
	overlays.write_overlays(config, out)
	(out / "alpha.yml").chmod(0o644)
	overlays.write_overlays(config, out)
	assert mode(out / "alpha.yml") == 0o600
	assert sorted(p.name for p in out.iterdir()) == [
		"alpha.yml",
		"beta.yml",
		"gamma.yml",
		"routes.tsv",
	]  # no temp files


def test_an_existing_loose_directory_is_tightened(setup):
	config, out = setup
	out.mkdir(mode=0o755)
	out.chmod(0o755)
	overlays.write_overlays(config, out)
	assert mode(out) == 0o700


def test_stale_overlays_are_found_by_their_marker_only(setup):
	config, out = setup
	overlays.write_overlays(config, out)
	(out / "removed.yml").write_text(
		overlays.TEMPLATE.format(bank="removed", url="http://127.0.0.1:1", key="x", bank_id='"removed"')
	)
	(out / "mine.yml").write_text("# my own file\nmemory: {}\n")
	(out / "empty.yml").write_text("")
	assert [p.name for p in overlays.stale_overlays(config, out)] == ["removed.yml"]


def test_load_overlay_requires_private_regular_file(setup, tmp_path):
	config, out = setup
	overlays.write_overlays(config, out, "https://memory.example")
	url, token = overlays.load_overlay(out / "alpha.yml")
	assert url == "https://memory.example" and token == load_keys(config).banks["alpha"]
	(out / "alpha.yml").chmod(0o640)
	with pytest.raises(ValueError, match="0600"):
		overlays.load_overlay(out / "alpha.yml")
	link = out / "link.yml"
	link.symlink_to(out / "beta.yml")
	with pytest.raises(OSError):
		overlays.load_overlay(link)  # symlinks are not followed
	(out / "bad.yml").write_text("hindsight: [unclosed")
	(out / "bad.yml").chmod(0o600)
	with pytest.raises(ValueError, match="valid YAML"):
		overlays.load_overlay(out / "bad.yml")
	(out / "empty.yml").write_text("memory: {}\n")
	(out / "empty.yml").chmod(0o600)
	with pytest.raises(ValueError, match="required"):
		overlays.load_overlay(out / "empty.yml")
	assert (
		overlays.overlay_bank(out / "beta.yml") == "beta" and overlays.overlay_bank(out / "empty.yml") is None
	)


def test_missing_pyyaml_fails_loudly_and_names_the_package(setup, monkeypatch):
	import sys

	from omp_hindsight_guard._yaml import MissingDependency

	config, out = setup
	overlays.write_overlays(config, out)
	monkeypatch.setitem(sys.modules, "yaml", None)
	with pytest.raises(MissingDependency, match="PyYAML"):
		overlays.load_overlay(out / "alpha.yml")
	with pytest.raises(MissingDependency, match="PyYAML"):
		overlays.overlay_bank(out / "alpha.yml")


def test_a_directory_with_other_files_is_refused_and_left_alone(setup, tmp_path):
	config, _ = setup
	other = tmp_path / "home-like"
	other.mkdir(mode=0o755)
	other.chmod(0o755)
	(other / "notes.txt").write_text("x")
	with pytest.raises(ValueError, match="not an overlay directory"):
		overlays.write_overlays(config, other)
	assert mode(other) == 0o755 and [p.name for p in other.iterdir()] == ["notes.txt"]
	file_path = tmp_path / "a-file"
	file_path.write_text("x")
	with pytest.raises(ValueError, match="not a directory"):
		overlays.write_overlays(config, file_path)
