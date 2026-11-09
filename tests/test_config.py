import json
import os
import stat

import pytest

from omp_hindsight_guard import config as cfg
from omp_hindsight_guard import proxy


def base(**banks):
	return {
		"version": 1,
		"proxy": {"upstream_key_file": "keys/upstream.key"},
		"banks": banks or {"work": {"key_file": "keys/work.key", "roots": ["~/code/work"]}},
	}


def write_key(path, value="k" * 40, mode=0o600):
	path.parent.mkdir(parents=True, exist_ok=True)
	path.write_text(value + "\n")
	path.chmod(mode)
	return path


def parse(data, tmp_path):
	return cfg.parse_config(data, tmp_path / "banks.json")


def test_minimal_config_has_safe_defaults(tmp_path):
	config = parse(base(), tmp_path)
	assert config.proxy.listen_host == "127.0.0.1" and config.proxy.listen_port == 8888
	assert config.proxy.upstream_url == "http://127.0.0.1:8890" and not config.proxy.allow_remote_listen
	assert config.proxy.local_url == "http://127.0.0.1:8888"
	assert config.proxy.upstream_key_file == tmp_path / "keys/upstream.key"
	(bank,) = config.banks
	assert (
		bank.name == "work" and bank.roots == ("~/code/work",) and bank.key_file == tmp_path / "keys/work.key"
	)
	assert config.importer.mnemopi_root is None and config.importer.exclude_labels == ()
	assert config.importer.allow_link_prefixes == ()


def test_any_number_of_banks_and_roots(tmp_path):
	banks = {f"b{i}": {"key_file": f"k/{i}.key", "roots": [f"~/p/{i}", f"/srv/{i}/"]} for i in range(25)}
	config = parse(base(**banks), tmp_path)
	assert [b.name for b in config.banks] == list(banks)
	assert config.routes[:2] == [("b0", "~/p/0"), ("b0", "/srv/0")]  # trailing slash dropped
	assert len(config.routes) == 50
	assert config.bank("b7").roots == ("~/p/7", "/srv/7")
	with pytest.raises(cfg.ConfigError):
		config.bank("missing")


def test_a_bank_may_have_no_roots(tmp_path):
	config = parse(base(solo={"key_file": "k"}), tmp_path)
	assert config.bank("solo").roots == ()


@pytest.mark.parametrize(
	("mutate", "message"),
	[
		(lambda d: d.update(version=2), "version"),
		(lambda d: d.update(version=True), "version"),
		(lambda d: d.update(extra=1), "unknown field 'extra'"),
		(lambda d: d.pop("proxy"), "missing field 'proxy'"),
		(lambda d: d["proxy"].update(listen_port=0), "listen_port"),
		(lambda d: d["proxy"].update(listen_port="8888"), "listen_port"),
		(lambda d: d["proxy"].update(listen_host="0.0.0.0"), "loopback"),
		(lambda d: d["proxy"].update(listen_host="example.com"), "loopback"),
		(lambda d: d["proxy"].update(nope=1), "unknown field 'nope'"),
		(lambda d: d["proxy"].pop("upstream_key_file"), "upstream_key_file"),
		(lambda d: d.update(banks={}), "at least one bank"),
		(lambda d: d["banks"].update({"bad name": {"key_file": "k"}}), "bank name"),
		(lambda d: d["banks"].update({"../x": {"key_file": "k"}}), "bank name"),
		(lambda d: d["banks"].update({"WORK": {"key_file": "k"}}), "ignoring case"),
		(lambda d: d["banks"]["work"].update(extra=1), "unknown field 'extra'"),
		(lambda d: d["banks"]["work"].pop("key_file"), "key_file"),
		(lambda d: d["banks"]["work"].update(roots="~/x"), "list of non-empty strings"),
		(lambda d: d["banks"]["work"].update(roots=["relative/path"]), "must start with"),
		(lambda d: d["banks"]["work"].update(roots=["~"]), "too broad"),
		(lambda d: d["banks"]["work"].update(roots=["/"]), "too broad"),
		(lambda d: d["banks"]["work"].update(roots=["~/a\tb"]), "control characters"),
		(lambda d: d["banks"]["work"].update(roots=["~/a\nb"]), "control characters"),
		(lambda d: d["banks"].update(other={"key_file": "k", "roots": ["~/code/WORK"]}), "already a root"),
		(lambda d: d.update({"import": {"allow_link_prefixes": ["http://x.example/"]}}), "https://"),
		(lambda d: d.update({"import": {"allow_link_prefixes": ["https://x.example/doc"]}}), "ending in '/'"),
		(lambda d: d.update({"import": {"mnemopi_root": 3}}), "mnemopi_root"),
		(lambda d: d.update({"import": {"bogus": []}}), "unknown field 'bogus'"),
	],
)
def test_invalid_configs_are_rejected_with_a_pointer(tmp_path, mutate, message):
	data = base()
	mutate(data)
	with pytest.raises(cfg.ConfigError, match=message):
		parse(data, tmp_path)


def test_remote_listen_is_explicit(tmp_path):
	data = base()
	data["proxy"].update(listen_host="192.0.2.10", allow_remote_listen=True)
	assert parse(data, tmp_path).proxy.listen_host == "192.0.2.10"
	data["proxy"]["listen_host"] = "not a host!"
	with pytest.raises(cfg.ConfigError, match="address or host name"):
		parse(data, tmp_path)
	data["proxy"].update(listen_host="::1", allow_remote_listen=False)
	assert parse(data, tmp_path).proxy.local_url == "http://[::1]:8888"
	data["proxy"].update(listen_host="::", allow_remote_listen=True)
	assert parse(data, tmp_path).proxy.local_url == "http://127.0.0.1:8888"


def test_load_config_reports_missing_invalid_and_duplicate(tmp_path):
	with pytest.raises(cfg.ConfigError, match="init"):
		cfg.load_config(tmp_path / "nope.json")
	bad = tmp_path / "bad.json"
	bad.write_text("{not json")
	with pytest.raises(cfg.ConfigError, match="not valid JSON"):
		cfg.load_config(bad)
	dup = tmp_path / "dup.json"
	dup.write_text('{"version": 1, "version": 1}')
	with pytest.raises(cfg.ConfigError, match="duplicate field 'version'"):
		cfg.load_config(dup)
	good = tmp_path / "good.json"
	good.write_text(json.dumps(base()))
	assert cfg.load_config(good).banks[0].name == "work"


def test_directories_follow_env_and_xdg(tmp_path):
	home = tmp_path / "h"
	assert cfg.config_dir({}, home) == home / ".config/omp-hindsight-guard"
	assert cfg.config_dir({"XDG_CONFIG_HOME": "/x"}, home).as_posix() == "/x/omp-hindsight-guard"
	assert cfg.config_dir({cfg.ENV_CONFIG_DIR: "/y"}, home).as_posix() == "/y"
	assert cfg.overlay_dir({}, home) == home / ".config/omp-hindsight-guard/overlays"
	assert cfg.overlay_dir({cfg.ENV_OVERLAY_DIR: "/o"}, home).as_posix() == "/o"
	assert cfg.state_dir({}, home) == home / ".local/state/omp-hindsight-guard"
	assert cfg.state_dir({"XDG_STATE_HOME": "/s"}, home).as_posix() == "/s/omp-hindsight-guard"
	assert cfg.state_dir({cfg.ENV_STATE_DIR: "/z"}, home).as_posix() == "/z"
	assert cfg.default_config_path({cfg.ENV_CONFIG_DIR: "/y"}).as_posix() == "/y/banks.json"


def test_key_files_must_be_private_and_well_formed(tmp_path):
	key = write_key(tmp_path / "a.key", "A" * 40)
	assert cfg.read_key(key, "t") == "A" * 40
	key.chmod(0o640)
	with pytest.raises(cfg.ConfigError, match="chmod 600"):
		cfg.read_key(key, "t")
	key.chmod(0o604)
	with pytest.raises(cfg.ConfigError, match="chmod 600"):
		cfg.read_key(key, "t")
	with pytest.raises(cfg.ConfigError, match="does not exist"):
		cfg.read_key(tmp_path / "missing.key", "t")
	with pytest.raises(cfg.ConfigError, match="not a regular file"):
		cfg.read_key(tmp_path, "t")
	for bad in ("short", "x" * 40 + " y", "x" * 39 + '"', "x" * 39 + "\\", "é" * 40, "x" * 600):
		write_key(tmp_path / "bad.key", bad)
		with pytest.raises(cfg.ConfigError):
			cfg.read_key(tmp_path / "bad.key", "t")


def test_error_messages_never_contain_a_key(tmp_path):
	secret = "S3cr3tKeyValue" * 4
	path = write_key(tmp_path / "k.key", secret + " ", 0o644)
	with pytest.raises(cfg.ConfigError) as err:
		cfg.read_key(path, "t")
	assert secret not in str(err.value)
	write_key(path, secret + '"')
	with pytest.raises(cfg.ConfigError) as err:
		cfg.read_key(path, "t")
	assert secret not in str(err.value)


def test_load_keys_needs_distinct_keys(tmp_path):
	data = base(a={"key_file": "keys/a.key"}, b={"key_file": "keys/b.key"})
	config = parse(data, tmp_path)
	write_key(tmp_path / "keys/upstream.key", "u" * 40)
	write_key(tmp_path / "keys/a.key", "a" * 40)
	write_key(tmp_path / "keys/b.key", "b" * 40)
	keys = cfg.load_keys(config)
	assert keys.upstream == "u" * 40 and keys.banks == {"a": "a" * 40, "b": "b" * 40}
	assert cfg.load_keys(config, ("b",)).banks == {"b": "b" * 40}
	write_key(tmp_path / "keys/b.key", "a" * 40)
	with pytest.raises(cfg.ConfigError, match="own key"):
		cfg.load_keys(config)
	write_key(tmp_path / "keys/b.key", "u" * 40)
	with pytest.raises(cfg.ConfigError, match="own key"):
		cfg.load_keys(config)


def test_proxy_config_from_settings(tmp_path):
	config = parse(base(a={"key_file": "keys/a.key"}, b={"key_file": "keys/b.key"}), tmp_path)
	write_key(tmp_path / "keys/upstream.key", "u" * 40)
	write_key(tmp_path / "keys/a.key", "a" * 40)
	write_key(tmp_path / "keys/b.key", "b" * 40)
	built = proxy.Config.from_settings(config.proxy, cfg.load_keys(config))
	assert built.bank_keys == {"a": "a" * 40, "b": "b" * 40} and built.port == 8888
	assert built.upstream_port == 8890 and built.host == "127.0.0.1"
	assert built.bank_for("Bearer " + "b" * 40) == "b"


def test_makedirs_private_creates_every_new_level_0700(tmp_path):
	existing = tmp_path / "existing"
	existing.mkdir(mode=0o755)
	existing.chmod(0o755)
	cfg.makedirs_private(existing / "a" / "b" / "c")
	assert stat.S_IMODE(existing.stat().st_mode) == 0o755  # left alone
	for part in ("a", "a/b", "a/b/c"):
		assert stat.S_IMODE((existing / part).stat().st_mode) == 0o700
	cfg.makedirs_private(existing / "a")  # idempotent
	os.umask(0o022)
