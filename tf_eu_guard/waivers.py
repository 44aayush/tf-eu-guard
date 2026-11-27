"""Reviewed waiver file: accepted mapped findings that stay visible in every report.

A waiver moves a finding out of the gate, never out of the reports. Waivers
only cover *mapped* findings (active or inline-suppressed); unmapped findings
cannot be waived.
"""

from dataclasses import dataclass, field, replace
from datetime import date, datetime, timedelta
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml

from tf_eu_guard.mapping.loader import RegistryValidationError, _UniqueKeyLoader
from tf_eu_guard.models import EnrichedFinding, Waiver

__all__ = [
    "WAIVER_FILENAME",
    "Waiver",
    "WaiverError",
    "WaiverResult",
    "apply_waivers",
    "load_waivers",
]

WAIVER_FILENAME = ".tf-eu-guard-waivers.yaml"
_REQUIRED = ("check_id", "resource", "owner", "reason", "expires")
_ALLOWED = {*_REQUIRED, "file"}


class WaiverError(ValueError):
    """The waiver file is unreadable or invalid (exit code 2)."""


@dataclass
class WaiverResult:
    """Outcome of matching waivers against findings."""

    active: list[EnrichedFinding]
    waived: list[EnrichedFinding]
    expired: list[Waiver] = field(default_factory=list)
    unused: list[Waiver] = field(default_factory=list)
    # Matched a finding but expire beyond ``today + max_days``; not applied.
    too_long: list[Waiver] = field(default_factory=list)


def _text(entry: dict[str, Any], key: str, where: str) -> str:
    value = entry[key]
    if not isinstance(value, str) or not value.strip():
        raise WaiverError(f"{where}: '{key}' must be a non-empty string")
    return value


def _parse_entry(entry: Any, index: int) -> Waiver:
    where = f"waivers[{index}]"
    if not isinstance(entry, dict):
        raise WaiverError(f"{where}: must be a mapping")
    if unknown := sorted(map(str, set(entry) - _ALLOWED)):
        raise WaiverError(f"{where}: unknown key(s) {unknown}")
    if missing := [k for k in _REQUIRED if k not in entry]:
        raise WaiverError(f"{where}: missing required key(s) {missing}")
    expires = entry["expires"]
    if isinstance(expires, datetime):
        expires = expires.date()
    elif isinstance(expires, str):
        try:
            expires = date.fromisoformat(expires)
        except ValueError:
            raise WaiverError(f"{where}: 'expires' is not an ISO date: {expires!r}") from None
    if not isinstance(expires, date):
        raise WaiverError(f"{where}: 'expires' must be a date (YYYY-MM-DD)")
    file = _text(entry, "file", where) if "file" in entry else None
    return Waiver(
        check_id=_text(entry, "check_id", where),
        resource=_text(entry, "resource", where),
        owner=_text(entry, "owner", where),
        reason=_text(entry, "reason", where),
        expires=expires,
        file=file,
    )


def load_waivers(path: Path) -> list[Waiver]:
    """Parse and validate a waiver file; raises :class:`WaiverError` on any problem."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        raise  # exit 2 via the existing handler
    except OSError as error:
        raise WaiverError(f"{path}: cannot read waiver file: {error}") from error
    try:
        data = yaml.load(text, Loader=_UniqueKeyLoader)  # noqa: S506 (SafeLoader subclass)
    except (yaml.YAMLError, RegistryValidationError) as error:
        raise WaiverError(f"{path}: invalid YAML: {error}") from error
    if not isinstance(data, dict):
        raise WaiverError(f"{path}: expected a mapping with schema_version and waivers")
    if data.get("schema_version") != 1:
        raise WaiverError(f"{path}: schema_version must be 1")
    if set(data) - {"schema_version", "waivers"}:
        raise WaiverError(
            f"{path}: unknown top-level key(s) {sorted(map(str, set(data) - {'schema_version', 'waivers'}))}"
        )
    entries = data.get("waivers")
    if not isinstance(entries, list):
        raise WaiverError(f"{path}: 'waivers' must be a list")
    try:
        return [_parse_entry(entry, i) for i, entry in enumerate(entries)]
    except WaiverError as error:
        raise WaiverError(f"{path}: {error}") from None


def _matches(waiver: Waiver, finding: EnrichedFinding) -> bool:
    if waiver.check_id != finding.check_id or waiver.resource != finding.resource:
        return False
    if waiver.file is None:
        return True
    path = finding.file_path.replace("\\", "/").lstrip("/")
    return fnmatchcase(path, waiver.file)


def apply_waivers(
    findings: list[EnrichedFinding],
    waivers: list[Waiver],
    today: date,
    max_days: int | None = None,
) -> WaiverResult:
    """Split ``findings`` into active and waived; a waiver is valid through its expiry date.

    With ``max_days``, a waiver expiring after ``today + max_days`` is not applied (it is listed
    in ``too_long`` when it matched a finding), so an unbounded expiry cannot waive forever.
    """
    limit = date.max
    if max_days is not None:
        try:
            limit = today + timedelta(days=max_days)
        except OverflowError:
            pass  # the limit lies beyond every representable date: nothing is too long
    result = WaiverResult([], [])
    matched: set[Waiver] = set()
    for finding in findings:
        hits = [w for w in waivers if _matches(w, finding)]
        matched.update(hits)
        valid = next((w for w in hits if today <= w.expires <= limit), None)
        if valid:
            result.waived.append(replace(finding, waiver=valid))
        else:
            result.active.append(finding)
    result.expired = [w for w in waivers if w.expires < today]
    result.too_long = [w for w in waivers if w in matched and w.expires > limit]
    result.unused = [w for w in waivers if w not in matched and w.expires >= today]
    return result
