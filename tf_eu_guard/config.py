"""Project configuration file (``.tf-eu-guard.yaml``).

Keys are the long CLI flags in snake_case. Precedence: CLI > config > default.
Only the scan root is searched for the file; parent directories never are.
"""

import argparse
from pathlib import Path
from typing import Any

import yaml

from tf_eu_guard.mapping.loader import RegistryValidationError, _UniqueKeyLoader

__all__ = ["CONFIG_FILENAME", "ConfigError", "find_config", "load_config"]

CONFIG_FILENAME = ".tf-eu-guard.yaml"
_STR_CHOICES = ("iac_type", "framework", "residency_policy")
_BOOLS = ("fail_on_any", "fail_on_suppressed", "fail_on_unmapped")
_STR_LISTS = ("allowed_regions", "exclude", "registry_dirs", "var_files")
_KEYS = {
    *_STR_CHOICES,
    *_BOOLS,
    *_STR_LISTS,
    "fail_on_severity",
    "timeout",
    "max_waiver_days",
    "waivers",
    "severity_overrides",
}


class ConfigError(ValueError):
    """The configuration file is unreadable or invalid (exit code 2)."""


def find_config(scan_path: Path | None) -> Path | None:
    """Return ``.tf-eu-guard.yaml`` in the scan root (a plan file's parent), if present."""
    if scan_path is None:
        return None
    root = scan_path if scan_path.is_dir() else scan_path.parent
    candidate = root / CONFIG_FILENAME
    return candidate if candidate.is_file() else None


def _strings(value: Any, key: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"'{key}' must be a list of strings")
    return value


def load_config(path: Path) -> dict[str, Any]:
    """Parse and validate a config file into argparse-dest-keyed values."""
    # Local import: the CLI package imports this module.
    from tf_eu_guard.cli.parser import (
        allowed_regions_arg,
        fail_on_severity_arg,
        max_waiver_days_arg,
        timeout_arg,
    )
    from tf_eu_guard.constants import FRAMEWORK_FILTERS, SUPPORTED_IAC_TYPES
    from tf_eu_guard.residency import RESIDENCY_POLICIES

    path = Path(path)
    try:
        data = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)  # noqa: S506
    except (OSError, UnicodeDecodeError) as error:
        raise ConfigError(f"{path}: cannot read config file: {error}") from error
    except (yaml.YAMLError, RegistryValidationError) as error:
        raise ConfigError(f"{path}: invalid YAML: {error}") from error
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: expected a mapping of settings")
    if unknown := sorted(set(data) - _KEYS):
        raise ConfigError(f"{path}: unknown key(s) {unknown}; valid keys: {sorted(_KEYS)}")

    choices = {
        "iac_type": SUPPORTED_IAC_TYPES,
        "framework": FRAMEWORK_FILTERS,
        "residency_policy": RESIDENCY_POLICIES,
    }
    out: dict[str, Any] = {}
    try:
        for key in _STR_CHOICES:
            if key in data:
                if data[key] not in choices[key]:
                    raise ConfigError(f"'{key}' must be one of {list(choices[key])}")
                out[key] = data[key]
        for key in _BOOLS:
            if key in data:
                if not isinstance(data[key], bool):
                    raise ConfigError(f"'{key}' must be true or false")
                out[key] = data[key]
        if "exclude" in data:
            out["exclude"] = _strings(data["exclude"], "exclude")
        if "allowed_regions" in data:
            try:
                out["allowed_regions"] = allowed_regions_arg(
                    ",".join(_strings(data["allowed_regions"], "allowed_regions"))
                )
            except argparse.ArgumentTypeError as error:
                raise ConfigError(f"'allowed_regions': {error}") from error
        if "fail_on_severity" in data:
            value = data["fail_on_severity"]
            if not isinstance(value, str):
                raise ConfigError("'fail_on_severity' must be a string")
            try:
                out["fail_on_severity"] = fail_on_severity_arg(value)
            except argparse.ArgumentTypeError as error:
                raise ConfigError(f"'fail_on_severity': {error}") from error
        if "timeout" in data:
            value = data["timeout"]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ConfigError("'timeout' must be a number")
            try:
                out["timeout"] = timeout_arg(str(value))
            except argparse.ArgumentTypeError as error:
                raise ConfigError(f"'timeout': {error}") from error
        if "max_waiver_days" in data:
            value = data["max_waiver_days"]
            if isinstance(value, bool) or not isinstance(value, int):
                raise ConfigError("'max_waiver_days' must be an integer")
            try:
                out["max_waiver_days"] = max_waiver_days_arg(str(value))
            except argparse.ArgumentTypeError as error:
                raise ConfigError(f"'max_waiver_days': {error}") from error
        if "waivers" in data:
            if not isinstance(data["waivers"], str):
                raise ConfigError("'waivers' must be a path string")
            out["waivers"] = path.parent / data["waivers"]
        if "registry_dirs" in data:
            out["registry_dirs"] = [
                path.parent / p for p in _strings(data["registry_dirs"], "registry_dirs")
            ]
        if "var_files" in data:
            out["var_files"] = [path.parent / p for p in _strings(data["var_files"], "var_files")]
        if "severity_overrides" in data:
            overrides = data["severity_overrides"]
            if not isinstance(overrides, dict):
                raise ConfigError("'severity_overrides' must map check IDs to severities")
            parsed: dict[str, str] = {}
            for check_id, severity in overrides.items():
                try:
                    level = fail_on_severity_arg(severity) if isinstance(severity, str) else None
                except argparse.ArgumentTypeError:
                    level = None
                if not level or not isinstance(check_id, str):
                    raise ConfigError(
                        f"'severity_overrides': {check_id}: {severity!r} is not a severity "
                        "(CRITICAL, HIGH, MEDIUM, LOW, INFO)"
                    )
                parsed[check_id] = level
            out["severity_overrides"] = parsed
    except ConfigError as error:
        raise ConfigError(f"{path}: {error}") from None
    return out
