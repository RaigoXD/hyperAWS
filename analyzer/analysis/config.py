"""Tunable thresholds and project-mapping settings (optional ``config/analyzer.toml``)."""

from __future__ import annotations

import copy
import math
import tomllib
from pathlib import Path

from ..fsutil import data_home

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PATH = data_home() / "config" / "analyzer.toml"

DEFAULTS: dict = {
    "thresholds": {
        "idle_cpu_avg": 5.0,            # % — running instance is "idle" when avg < this ...
        "idle_cpu_max": 20.0,           # ... and max < this over the metrics window
        "oversized_cpu_avg": 15.0,
        "oversized_cpu_max": 40.0,
        "stopped_instance_days": 14,
        "unattached_volume_days": 3,
        "old_snapshot_days": 90,
        "ami_unused_days": 90,
        "nat_idle_bytes": 1_000_000,    # < 1 MB in/out over the window == unused NAT
        "unused_days_long": 30,
        "stale_iam_days": 90,
        "rds_snapshot_orphan_days": 30,
        "rds_snapshot_old_days": 365,
        "s3_lifecycle_min_gb": 100,
        "log_min_gb": 0.5,
        "min_insight_usd": 5.0,         # don't show aggregated insights smaller than this
        "ddb_overprovisioned_util": 0.2,
        "ecs_low_cpu_avg": 10.0,
        "idle_network_bytes_per_day": 100e6,   # an instance moving more than ~100 MB/day is not idle even at low CPU
        "cache_idle_connections": 3,           # ElastiCache keeps a few monitoring/replication connections open
    },
    "assumptions": {                    # used for "typical savings" insights; all approximate
        "nonprod_schedule_saving": 0.65,   # stop 12h/day on weekdays => ~65% less runtime
        "s3_lifecycle_saving": 0.25,
        "log_retention_saving": 0.5,
        "nonprod_envs": ["dev", "staging", "test"],
    },
    "projects": {
        "tag_keys": ["Project", "project", "Application", "application", "App", "app", "Service", "service",
                     "Product", "product", "Workload", "workload", "Team", "team", "Owner", "owner"],
        "env_tag_keys": ["Environment", "environment", "Env", "env", "Stage", "stage"],
        "use_stack_name": True,
        "use_name_prefix": True,
        "min_prefix_group": 3,
        "generic_tokens": ["prod", "production", "prd", "dev", "development", "test", "testing", "qa", "uat", "stg",
                           "stage", "staging", "preprod", "sandbox", "app", "web", "api", "aws", "default", "main",
                           "my", "the", "terraform", "cloudformation", "stack", "eks", "ecs", "rds", "lambda",
                           "vpc", "subnet", "sg", "igw", "nat", "alb", "nlb", "elb", "ec2", "s3", "db", "cache",
                           "public", "private", "internal", "external", "new", "old", "tmp", "temp", "backup"],
    },
    "rules": [],      # [[rules]] project mapping rules, evaluated in order (see analyzer.example.toml)
}


class ConfigError(ValueError):
    """analyzer.toml has an unknown key, a value of the wrong type or a pattern that does not compile."""


_FRACTIONS = {"nonprod_schedule_saving", "s3_lifecycle_saving", "log_retention_saving"}   # shares of a cost: 0..1
_STR_LISTS = {"nonprod_envs", "tag_keys", "env_tag_keys", "generic_tokens"}
_BOOLS = {"use_stack_name", "use_name_prefix"}


def _is_number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def str_list(v, where: str) -> list[str]:
    """A list of strings; a single string is accepted as a one-item list (never iterated character by character)."""
    if isinstance(v, str):
        v = [v]
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ConfigError(f"{where} must be a list of strings, e.g. [\"a\", \"b\"]")
    return v


def _check_sections(user: dict) -> None:
    """Types and names of the [thresholds]/[assumptions]/[projects] settings (str -> [str] is normalised in place)."""
    unknown = set(user) - set(DEFAULTS)
    if unknown:
        raise ConfigError(f"unknown section(s) {sorted(unknown)}; allowed: {sorted(DEFAULTS)}")
    for section in ("thresholds", "assumptions", "projects"):
        if section not in user:
            continue
        values = user[section]
        if not isinstance(values, dict):
            raise ConfigError(f"[{section}] must be a table")
        unknown = set(values) - set(DEFAULTS[section])
        if unknown:
            raise ConfigError(f"[{section}]: unknown key(s) {sorted(unknown)}; allowed: {sorted(DEFAULTS[section])}")
        for key, v in values.items():
            where = f"{section}.{key}"
            if key in _STR_LISTS:
                values[key] = str_list(v, where)
            elif key in _BOOLS:
                if not isinstance(v, bool):
                    raise ConfigError(f"{where} must be true or false")
            elif key == "min_prefix_group":
                if not (isinstance(v, int) and not isinstance(v, bool) and v >= 1):
                    raise ConfigError(f"{where} must be a whole number >= 1")
            elif not _is_number(v) or v < 0:
                raise ConfigError(f"{where} must be a number >= 0 (got {v!r})")
            elif key in _FRACTIONS and v > 1:
                raise ConfigError(f"{where} is a share of the cost: a number between 0 and 1 (got {v!r})")


def _merge(base: dict, over: dict) -> dict:
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = v
    return base


def load_config(path: str | Path | None = None) -> dict:
    """Defaults, overlaid with ``path`` (or config/analyzer.toml when it exists). Every value is type-checked and every
    rule pattern compiled here, so a mistake is a :class:`ConfigError` naming the file and key, not a traceback
    mid-analysis or a silently wrong grouping."""
    from .grouping import validate_rules
    cfg = copy.deepcopy(DEFAULTS)
    p = Path(path) if path else DEFAULT_PATH
    if p.exists():
        try:
            with p.open("rb") as f:
                user = tomllib.load(f)
        except tomllib.TOMLDecodeError as e:
            raise ConfigError(f"{p}: not valid TOML: {e}") from None
        try:
            _check_sections(user)
            _merge(cfg, {k: v for k, v in user.items() if k != "rules"})
            if "rules" in user:
                cfg["rules"] = user["rules"]
            validate_rules(cfg["rules"])
        except ValueError as e:
            raise ConfigError(f"{p}: {e}") from None
    elif path:
        raise FileNotFoundError(f"config file not found: {p}")
    return cfg
