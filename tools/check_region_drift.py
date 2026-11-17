#!/usr/bin/env python3
"""Report AWS regions known to botocore but missing from KNOWN_AWS_REGIONS.

``tf_eu_guard/regions.py`` is maintained by hand; a region missing from it
makes ``EUGUARD_GDPR_002``/``003`` return UNKNOWN instead of FAIL. This tool
compares it with botocore's partition data.

    python3 tools/check_region_drift.py                 # installed botocore
    python3 tools/check_region_drift.py PATH            # endpoints.json /
                                                        # partitions.json, or a
                                                        # directory holding one

botocore is NOT a dependency of tf-eu-guard; run this in a tooling
environment with a current botocore (for example from a scheduled CI job).

Exit codes: 0 = no drift, 1 = regions missing, 2 = data could not be loaded.
Regions in the table but absent from botocore are informational only (the
table deliberately also lists the EU Sovereign Cloud and similar regions).
"""

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tf_eu_guard.regions import KNOWN_AWS_REGIONS, UNCLASSIFIED_AWS_REGIONS  # noqa: E402

DATA_FILES = ("endpoints.json", "partitions.json")


def _resolve(path: Path) -> Path:
    if path.is_dir():
        for name in DATA_FILES:
            if (path / name).is_file():
                return path / name
        raise FileNotFoundError(f"no {' or '.join(DATA_FILES)} in {path}")
    return path


def load_botocore_regions(path: Path | None = None) -> dict[str, set[str]]:
    """Return ``{partition: {region, ...}}`` from botocore partition data."""
    if path is None:
        try:
            import botocore  # type: ignore[import-not-found,unused-ignore]
        except ImportError as exc:
            raise FileNotFoundError(
                "botocore is not installed; pass a path to endpoints.json"
            ) from exc
        path = Path(botocore.__file__).parent / "data"
    document = json.loads(_resolve(path).read_text(encoding="utf-8"))
    partitions = document.get("partitions")
    if not isinstance(partitions, list):
        raise ValueError("partition data has no 'partitions' list")
    result: dict[str, set[str]] = {}
    for partition in partitions:
        name = str(partition.get("partition", "unknown"))
        regions = partition.get("regions", {})
        result.setdefault(name, set()).update(str(r) for r in regions)
    return result


def find_missing(
    botocore_regions: dict[str, set[str]],
    known: frozenset[str] = KNOWN_AWS_REGIONS | UNCLASSIFIED_AWS_REGIONS,
) -> dict[str, list[str]]:
    """Return ``{partition: sorted missing regions}`` (empty partitions omitted)."""
    missing = {p: sorted(r - known) for p, r in botocore_regions.items()}
    return {p: r for p, r in sorted(missing.items()) if r}


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    try:
        regions = load_botocore_regions(Path(args[0]) if args else None)
    except (OSError, ValueError) as exc:
        print(f"region drift check could not run: {exc}", file=sys.stderr)
        return 2
    missing = find_missing(regions)
    if not missing:
        total = sum(len(r) for r in regions.values())
        print(f"region table OK ({total} botocore regions, none missing)")
        return 0
    print("REGION DRIFT: botocore lists regions missing from KNOWN_AWS_REGIONS:", file=sys.stderr)
    for partition, names in missing.items():
        print(f"  {partition}: {', '.join(names)}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
