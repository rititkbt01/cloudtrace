"""Settings for one analysis run, with safe defaults and simple validation."""

DEFAULTS = {
    # How long after a key is created we look for its first use (Check 2).
    "window_minutes": 60,
    # How many earlier events an identity needs before its "usual addresses" are trusted (Check 2).
    "baseline_min_events": 3,
    # Names of approved automation roles that may create keys for others (Check 1).
    "allowed_roles": [],
    # Policies treated as strong rights when granted (Check 3).
    "elevated_policies": ["arn:aws:iam::aws:policy/AdministratorAccess"],
}


class ConfigError(ValueError):
    """A setting is missing its expected type or value. The message says which one."""


def resolve(config: dict | None) -> dict:
    """Return a full settings dict: defaults filled in, unknown names rejected."""
    config = dict(config or {})
    unknown = sorted(set(config) - set(DEFAULTS))
    if unknown:
        raise ConfigError(f"Unknown setting(s): {', '.join(unknown)}")
    out = {k: (list(v) if isinstance(v, list) else v) for k, v in DEFAULTS.items()}
    out.update(config)
    for name in ("window_minutes", "baseline_min_events"):
        v = out[name]
        if isinstance(v, bool) or not isinstance(v, int) or v < 1:
            raise ConfigError(f"{name} must be a whole number of at least 1")
    for name in ("allowed_roles", "elevated_policies"):
        v = out[name]
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            raise ConfigError(f"{name} must be a list of text values")
    return out


def load(path) -> dict:
    """Read a TOML settings file (see rules/default.toml) and return resolved settings."""
    import tomllib
    from pathlib import Path

    p = Path(path)
    try:
        with p.open("rb") as f:
            data = tomllib.load(f)
    except OSError as err:
        raise ConfigError(f"Cannot read settings file {p.name}: {err}") from err
    except tomllib.TOMLDecodeError as err:
        raise ConfigError(f"Settings file {p.name} is not valid TOML: {err}") from err
    return resolve(data)
