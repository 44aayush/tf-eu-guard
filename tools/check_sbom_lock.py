"""Verify that a generated CycloneDX SBOM represents the runtime lock exactly."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def _normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _lock_components(lock_path: Path) -> set[tuple[str, str]]:
    text = lock_path.read_text(encoding="utf-8")
    return {
        (_normalise(match.group(1)), match.group(2))
        for match in re.finditer(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)", text, re.MULTILINE)
    }


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} LOCKFILE SBOM.json", file=sys.stderr)
        return 2
    lock_components = _lock_components(Path(sys.argv[1]))
    sbom = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    sbom_components = {
        (_normalise(component["name"]), component["version"])
        for component in sbom.get("components", [])
    }
    missing = sorted(lock_components - sbom_components)
    extra = sorted(sbom_components - lock_components)
    if missing or extra:
        if missing:
            print(f"ERROR: SBOM is missing locked components: {missing}", file=sys.stderr)
        if extra:
            print(f"ERROR: SBOM contains components absent from lock: {extra}", file=sys.stderr)
        return 1
    print(f"OK: SBOM and lock contain the same {len(lock_components)} components")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
