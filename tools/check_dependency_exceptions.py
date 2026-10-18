"""Validate the bounded dependency advisory exceptions used by CI."""

from __future__ import annotations

import json
import re
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXCEPTIONS_PATH = ROOT / "dependency-exceptions.json"
LOCK_PATH = ROOT / "requirements.lock"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
REQUIRED_FIELDS = {
    "advisory",
    "owner",
    "package",
    "locked_version",
    "introduced_by",
    "rationale",
    "mitigation",
    "review_date",
    "expiry_date",
}


def _normalise_package(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _lock_versions(text: str) -> dict[str, str]:
    versions: dict[str, str] = {}
    for match in re.finditer(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)", text, re.MULTILINE):
        versions[_normalise_package(match.group(1))] = match.group(2)
    return versions


def main() -> int:
    data = json.loads(EXCEPTIONS_PATH.read_text(encoding="utf-8"))
    today = date.today()
    errors: list[str] = []
    if not data.get("owner"):
        errors.append("top-level owner is required")

    exceptions = data.get("exceptions")
    if not isinstance(exceptions, list) or not exceptions:
        errors.append("exceptions must be a non-empty list")
        exceptions = []

    lock_versions = _lock_versions(LOCK_PATH.read_text(encoding="utf-8"))
    seen: set[str] = set()
    exception_ids: set[str] = set()
    for index, exception in enumerate(exceptions, start=1):
        if not isinstance(exception, dict):
            errors.append(f"exception {index} must be an object")
            continue
        missing = REQUIRED_FIELDS - exception.keys()
        if missing:
            errors.append(f"exception {index} missing: {', '.join(sorted(missing))}")
            continue

        advisory = str(exception["advisory"])
        package = _normalise_package(str(exception["package"]))
        if advisory in seen:
            errors.append(f"duplicate advisory {advisory}")
        seen.add(advisory)
        exception_ids.add(advisory)

        locked = lock_versions.get(package)
        if locked != str(exception["locked_version"]):
            errors.append(
                f"{advisory}: {package} lock is {locked!r}, expected "
                f"{exception['locked_version']!r}"
            )
        try:
            review = date.fromisoformat(str(exception["review_date"]))
            expiry = date.fromisoformat(str(exception["expiry_date"]))
        except ValueError as error:
            errors.append(f"{advisory}: invalid review/expiry date: {error}")
            continue
        if review > expiry:
            errors.append(f"{advisory}: review_date must not be after expiry_date")
        if expiry <= today:
            errors.append(f"{advisory}: exception expired on {expiry.isoformat()}")

    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    workflow_ids = set(re.findall(r"--ignore-vuln\s+([A-Za-z0-9-]+)", workflow))
    if workflow_ids != exception_ids:
        errors.append(
            "CI ignore list differs from dependency-exceptions.json: "
            f"workflow={sorted(workflow_ids)}, record={sorted(exception_ids)}"
        )

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(
        f"OK: {len(exception_ids)} dependency advisory exceptions valid; "
        f"none expire on or before {today.isoformat()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
