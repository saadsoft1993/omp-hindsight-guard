import pytest

from omp_hindsight_guard import routing
from omp_hindsight_guard.config import parse_config

BANKS = [
	("alpha", "~/work/alpha-app"),
	("alpha", "~/work/tools"),
	("beta", "~/work/beta-site"),
]


@pytest.fixture
def home(tmp_path):
	home = tmp_path / "home"
	for d in ("work/beta-site/web", "work/alpha-app/ui", "work/tools"):
		(home / d).mkdir(parents=True)
	(home / "work/other").mkdir()
	return home


def test_roots_come_from_banks_json_in_file_order(tmp_path):
	config = parse_config(
		{
			"version": 1,
			"proxy": {"upstream_key_file": "u.key"},
			"banks": {
				"alpha": {"key_file": "a.key", "roots": ["~/work/alpha-app", "~/work/tools"]},
				"beta": {"key_file": "b.key", "roots": ["~/work/beta-site"]},
			},
		},
		tmp_path / "banks.json",
	)
	assert config.routes == BANKS
	assert routing.routes_table(config) == (
		"alpha\t~/work/alpha-app\nalpha\t~/work/tools\nbeta\t~/work/beta-site\n"
	)


def test_allow_list_and_no_default(home):
	assert routing.bank_for_path(home / "work/beta-site/web", BANKS, home) == "beta"
	assert routing.bank_for_path(home / "work/beta-site", BANKS, home) == "beta"
	assert routing.bank_for_path(home / "work/alpha-app/ui", BANKS, home) == "alpha"
	assert routing.bank_for_path(home / "work/tools", BANKS, home) == "alpha"
	assert routing.bank_for_path(home / "work/beta-site-other", BANKS, home) is None
	assert routing.bank_for_path(home / "work/other", BANKS, home) is None
	assert routing.bank_for_path(home / "work", BANKS, home) is None
	assert routing.bank_for_path("/elsewhere", BANKS, home) is None


def test_absolute_roots_are_not_relative_to_home(home, tmp_path):
	outside = tmp_path / "elsewhere"
	(outside / "sub").mkdir(parents=True)
	banks = [("gamma", str(outside))]
	assert routing.bank_for_path(outside / "sub", banks, home) == "gamma"
	assert routing.bank_for_path(home, banks, home) is None


def test_case_variant_and_symlinks(home, tmp_path):
	assert routing.bank_for_path(str(home / "Work/Beta-Site/WEB"), BANKS, home) == "beta"
	link_in = home / "work/alpha-app/beta-link"
	link_in.symlink_to(home / "work/beta-site/web")
	assert routing.bank_for_path(link_in, BANKS, home) == "beta"
	link_out = tmp_path / "outside-link"
	link_out.symlink_to(home / "work/alpha-app")
	assert routing.bank_for_path(link_out / "ui", BANKS, home) == "alpha"
	home_link = tmp_path / "home-link"
	home_link.symlink_to(home)
	assert routing.bank_for_path(home / "work/beta-site", BANKS, home_link) == "beta"


def test_longest_root_wins(home):
	banks = [("wide", "~/work"), ("narrow", "~/work/beta-site"), ("narrowest", "~/work/beta-site/web")]
	assert routing.bank_for_path(home / "work/beta-site/api", banks, home) == "narrow"
	assert routing.bank_for_path(home / "work/beta-site/web/x", banks, home) == "narrowest"
	assert routing.bank_for_path(home / "work/other", banks, home) == "wide"


def test_many_banks(home):
	banks = [(f"bank{i}", f"~/many/{i}") for i in range(50)]
	for i in (0, 7, 49):
		(home / f"many/{i}/sub").mkdir(parents=True)
		assert routing.bank_for_path(home / f"many/{i}/sub", banks, home) == f"bank{i}"
	assert routing.bank_for_path(home / "many", banks, home) is None


def test_missing_cwd_is_routed_by_string_and_flagged(home):
	gone = home / "work/beta-site/deleted-repo/sub"
	assert not gone.exists()
	assert routing.route(gone, BANKS, home) == routing.Route("beta", True)
	assert routing.route(home / "work/beta-site/web", BANKS, home) == routing.Route("beta", False)
	assert routing.route(home / "gone/Old", BANKS, home) == routing.Route(None, True)
	assert routing.route(str(home / "work/beta-site/x/../../other"), BANKS, home).bank is None
