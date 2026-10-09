import pytest

from cloudtrace.config import DEFAULTS, ConfigError, resolve


def test_defaults_are_filled_in():
    assert resolve(None) == DEFAULTS
    assert resolve({"window_minutes": 30})["baseline_min_events"] == DEFAULTS["baseline_min_events"]


def test_defaults_object_is_not_shared():
    resolve(None)["allowed_roles"].append("x")
    assert DEFAULTS["allowed_roles"] == []


@pytest.mark.parametrize("bad", [
    {"window_minutes": 0}, {"window_minutes": "60"}, {"window_minutes": True},
    {"allowed_roles": "ci"}, {"elevated_policies": [1]}, {"typo_setting": 1},
])
def test_bad_settings_are_rejected(bad):
    with pytest.raises(ConfigError):
        resolve(bad)


def test_load_default_settings_file():
    from pathlib import Path

    from cloudtrace.config import load
    assert load(Path(__file__).resolve().parent.parent / "rules" / "default.toml") == DEFAULTS


def test_load_errors_are_clear(tmp_path):
    from cloudtrace.config import load
    with pytest.raises(ConfigError, match="Cannot read"):
        load(tmp_path / "missing.toml")
    (tmp_path / "bad.toml").write_text("not = = toml")
    with pytest.raises(ConfigError, match="not valid TOML"):
        load(tmp_path / "bad.toml")
