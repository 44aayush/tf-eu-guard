#!/usr/bin/env python3
"""Check the Azure and GCP location tables against reviewed snapshots.

``tf_eu_guard/regions.py`` is maintained by hand. ``tools/region_snapshots/azure.json``
and ``gcp.json`` record the last reviewed state of each provider's region list
(source URL, verification date, and the codes classified as EU/EEA, third country
or deliberately unclassified). This tool fails when a table and its snapshot
disagree, so a table edit has to be paired with a reviewed snapshot edit.

    python3 tools/check_cloud_region_tables.py

The tool is offline. Refreshing a snapshot against the provider's published list
is a manual step; see tools/README.md.

Exit codes: 0 = tables match the snapshots, 1 = drift, 2 = a snapshot could not
be loaded.
"""

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tf_eu_guard import regions  # noqa: E402

SNAPSHOT_DIR = REPO_ROOT / "tools" / "region_snapshots"
REQUIRED_KEYS = ("source", "verified", "eu_eea", "third_country", "unclassified")

# provider -> (snapshot file, EU/EEA table name, known table name) in tf_eu_guard.regions
PROVIDERS = {
    "azure": ("azure.json", "AZURE_EU_EEA_LOCATIONS", "AZURE_KNOWN_LOCATIONS"),
    "gcp": ("gcp.json", "GCP_EU_EEA_LOCATIONS", "GCP_KNOWN_LOCATIONS"),
}


def load_snapshot(path: Path) -> dict:
    document = json.loads(path.read_text(encoding="utf-8"))
    missing = [key for key in REQUIRED_KEYS if key not in document]
    if missing:
        raise ValueError(f"{path.name}: missing keys {', '.join(missing)}")
    for key in REQUIRED_KEYS[2:]:
        value = document[key]
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError(f"{path.name}: {key} must be a list of strings")
    return document


def find_drift(provider: str, snapshot: dict) -> list[str]:
    """Return human-readable drift lines for one provider (empty = in sync)."""
    _, eu_name, known_name = PROVIDERS[provider]
    eu_eea = set(getattr(regions, eu_name))
    third_country = set(getattr(regions, known_name)) - eu_eea
    problems = []
    for label, table, recorded in (
        ("eu_eea", eu_eea, set(snapshot["eu_eea"])),
        ("third_country", third_country, set(snapshot["third_country"])),
    ):
        for code in sorted(table - recorded):
            problems.append(f"{provider}: {code} is in the {label} table but not the snapshot")
        for code in sorted(recorded - table):
            problems.append(f"{provider}: {code} is in the {label} snapshot but not the table")
    for code in sorted(set(snapshot["third_country"]) & eu_eea):
        problems.append(f"{provider}: {code} is EU/EEA but listed as a third country")
    for code in sorted(set(snapshot["unclassified"]) & (eu_eea | third_country)):
        problems.append(f"{provider}: {code} is unclassified in the snapshot but classified")
    return problems


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    snapshot_dir = Path(args[0]) if args else SNAPSHOT_DIR
    problems: list[str] = []
    for provider, (filename, _, _) in PROVIDERS.items():
        try:
            snapshot = load_snapshot(snapshot_dir / filename)
        except (OSError, ValueError) as exc:
            print(f"region table check could not run: {exc}", file=sys.stderr)
            return 2
        problems.extend(find_drift(provider, snapshot))
    if not problems:
        print("Azure/GCP region tables OK (match snapshots)")
        return 0
    print("REGION TABLE DRIFT:", file=sys.stderr)
    for line in problems:
        print(f"  {line}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
