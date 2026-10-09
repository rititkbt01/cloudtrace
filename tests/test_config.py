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
