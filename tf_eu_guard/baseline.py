"""Finding identity and baseline files (N-05, N-16).

A baseline is a previous JSON report (object v1/v2 or the legacy array). Findings
are compared by ``(check_id, resource, normalised file path)``; line numbers are
left out on purpose so unrelated edits do not make a known finding look new.
"""

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class BaselineError(ValueError):
    """The baseline (or diff input) file is unreadable or not a tf-eu-guard report."""


Key = tuple[str, str, str]


def finding_key(check_id: str, resource: str | None, file_path: str | None) -> Key:
    """Stable identity of a finding across scans."""
    path = (file_path or "").replace("\\", "/")
    return (check_id, resource or "", path[1:] if path.startswith("/") else path)


@dataclass
class Baseline:
    keys: frozenset[Key]
    created: datetime | None


def read_entries(path: Path) -> tuple[list[dict[str, Any]], datetime | None]:
    """Return the active finding entries of a report and its scan time (if recorded).

    Entries flagged ``suppressed`` or ``waived`` are skipped. Baselined findings
    (the object format's ``baselined[]``, or array entries flagged ``baselined``)
    count as present: they are still failing checks.
    """
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise
    except json.JSONDecodeError as error:
        raise BaselineError(f"{path}: not valid JSON ({error})") from error
    except UnicodeDecodeError as error:
        raise BaselineError(f"{path}: not UTF-8 text ({error})") from error
    except OSError as error:
        raise BaselineError(f"{path}: cannot be read ({error})") from error

    created: datetime | None = None
    if isinstance(document, list):
        raw: Any = document
    elif isinstance(document, dict) and isinstance(document.get("findings"), list):
        known = document.get("baselined", [])
        scan = document.get("scan", {})
        if not isinstance(known, list) or not isinstance(scan, dict):
            raise BaselineError(f"{path}: 'baselined' must be an array and 'scan' an object")
        raw = [*document["findings"], *known]
        stamp = scan.get("timestamp")
        if isinstance(stamp, str):
            try:
                created = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
            except ValueError:
                created = None
    else:
        raise BaselineError(
            f"{path}: not a tf-eu-guard JSON report (expected an object with 'findings' or an array)"
        )
    entries = []
    for item in raw:
        if not isinstance(item, dict) or not isinstance(item.get("check_id"), str):
            raise BaselineError(f"{path}: every finding entry needs a string 'check_id'")
        if not (item.get("suppressed") or item.get("waived")):
            entries.append(item)
    return entries, created


def entry_key(entry: dict[str, Any]) -> Key:
    return finding_key(entry["check_id"], entry.get("resource"), entry.get("file_path"))


def load_baseline(path: Path) -> Baseline:
    """Load the known-finding keys of a previous report."""
    entries, created = read_entries(path)
    return Baseline(frozenset(entry_key(e) for e in entries), created)
