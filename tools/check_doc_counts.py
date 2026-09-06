#!/usr/bin/env python3
"""Verify that every mapping count in the docs matches the registries.

The README drifted before — stale "38"/"44"/"30" leftovers sat alongside the
real figures (AWS 116 · Azure 23 · GCP 22 · Kubernetes 24) because every
number was hand-typed. This script computes the counts directly from
``tf_eu_guard/mapping/registry-*.yaml`` and fails when a documented number
disagrees, so the drift can't recur.

Run standalone (CI does):

    python3 tools/check_doc_counts.py

Exit codes: 0 = every documented count matches, 1 = at least one mismatch
(or a documented number could not be found — rewording a doc line without
updating CHECKS below is also a failure, by design).
"""

import re
import sys
from collections import Counter
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
MAPPING_DIR = REPO_ROOT / "tf_eu_guard" / "mapping"

TF_CLOUD_REGISTRIES = ("registry-aws", "registry-azure", "registry-gcp")


def compute_counts() -> dict[str, int]:
    """Count registry entries per file, per framework, and per severity."""
    entries: dict[str, dict] = {}
    for path in sorted(MAPPING_DIR.glob("registry-*.yaml")):
        entries[path.stem] = yaml.safe_load(path.read_text()) or {}

    counts: dict[str, int] = {"total": sum(len(v) for v in entries.values())}
    for name, data in entries.items():
        counts[name.removeprefix("registry-")] = len(data)

    def framework_count(names: tuple[str, ...], framework: str) -> int:
        return sum(
            1
            for name in names
            for mapping in entries[name].values()
            if any(a["framework"] == framework for a in mapping["articles"])
        )

    counts["tf_nis2"] = framework_count(TF_CLOUD_REGISTRIES, "NIS2")
    counts["tf_gdpr"] = framework_count(TF_CLOUD_REGISTRIES, "GDPR")
    # GDPR Art. 32(1) specifically: the tf GDPR total minus the Art. 44 custom
    # check, which the docs list as its own scope-table row.
    counts["tf_gdpr_32"] = counts["tf_gdpr"] - int(
        "EUGUARD_GDPR_001" in entries.get("registry-aws", {})
    )
    counts["k8s_nis2"] = framework_count(("registry-kubernetes",), "NIS2")
    counts["k8s_gdpr"] = framework_count(("registry-kubernetes",), "GDPR")

    severity = Counter(
        mapping["severity"]
        for mapping in entries["registry-aws"].values()
    )
    counts["aws_critical"] = severity["CRITICAL"]
    counts["aws_high"] = severity["HIGH"]
    counts["aws_medium"] = severity["MEDIUM"]
    counts["aws_low"] = severity["LOW"]
    return counts


#: (file, regex, expected, what-it-is). One capture group per expected int —
#: a tuple means several groups in one documented sentence.
#: Keep in sync with the wording in the docs; if you reword a line, update its
#: pattern here in the same commit.
CHECKS: list[tuple[str, re.Pattern, int | tuple[int, ...], str]] = [
    # --- README.md ---
    ("README.md", re.compile(r"mappings-(\d+)-orange"), "total", "badge total mappings"),
    ("README.md", re.compile(r"\*\*(\d+) Checkov checks mapped\*\*"), "total", "registry section total"),
    ("README.md", re.compile(r"AWS: (\d+) mappings"), "aws", "AWS mappings"),
    ("README.md", re.compile(r"Azure: (\d+)"), "azure", "Azure mappings"),
    ("README.md", re.compile(r"GCP: (\d+)"), "gcp", "GCP mappings"),
    ("README.md", re.compile(r"Kubernetes: (\d+)"), "kubernetes", "Kubernetes mappings"),
    ("README.md", re.compile(r"\*\*Azure\*\* \((\d+)\)"), "azure", "Azure bullet"),
    ("README.md", re.compile(r"\*\*GCP\*\* \((\d+)\)"), "gcp", "GCP bullet"),
    ("README.md", re.compile(r"\*\*Kubernetes\*\* \((\d+)\)"), "kubernetes", "Kubernetes bullet"),
    # Scope table (row-anchored so column reordering can't silently detach a
    # number from its row).
    (
        "README.md",
        re.compile(r"\*\*NIS2 Article 21\(2\)\*\* \| ✅ (\d+) cloud check mappings"),
        "tf_nis2",
        "scope table: NIS2 terraform-source mappings",
    ),
    (
        "README.md",
        re.compile(r"\*\*GDPR Article 32\(1\)\*\* \| ✅ (\d+) cloud check mappings"),
        "tf_gdpr_32",
        "scope table: GDPR Art. 32(1) terraform-source mappings",
    ),
    (
        "README.md",
        re.compile(
            r"\*\*NIS2 Article 21\(2\)\*\* \| ✅ \d+ cloud check mappings "
            r"\| ✅ same checks apply \| ✅ (\d+) `CKV_K8S_\*` mappings"
        ),
        "k8s_nis2",
        "scope table: NIS2 kubernetes mappings",
    ),
    (
        "README.md",
        re.compile(
            r"\*\*GDPR Article 32\(1\)\*\* \| ✅ \d+ cloud check mappings "
            r"\| ✅ same checks apply \| ✅ (\d+) `CKV_K8S_\*` mappings"
        ),
        "k8s_gdpr",
        "scope table: GDPR kubernetes mappings",
    ),
    # --- CONTRIBUTING.md ---
    ("CONTRIBUTING.md", re.compile(r"AWS \((\d+) mappings"), "aws", "registry table: AWS"),
    ("CONTRIBUTING.md", re.compile(r"Azure \((\d+) mappings\)"), "azure", "registry table: Azure"),
    ("CONTRIBUTING.md", re.compile(r"GCP \((\d+) mappings\)"), "gcp", "registry table: GCP"),
    (
        "CONTRIBUTING.md",
        re.compile(r"Kubernetes `CKV_K8S_\*` \((\d+) mappings\)"),
        "kubernetes",
        "registry table: Kubernetes",
    ),
    # --- docs/check-mapping-table.md ---
    (
        "docs/check-mapping-table.md",
        re.compile(r"\*\*(\d+) check IDs\*\*"),
        "aws",
        "mapped check IDs in registry-aws.yaml",
    ),
    (
        "docs/check-mapping-table.md",
        re.compile(r"(\d+) total: (\d+) CRITICAL · (\d+) HIGH · (\d+) MEDIUM · (\d+) LOW"),
        ("aws", "aws_critical", "aws_high", "aws_medium", "aws_low"),
        "AWS severity distribution",
    ),
    (
        "docs/check-mapping-table.md",
        re.compile(
            r"\*\*(\d+) CRITICAL · (\d+) HIGH · (\d+) MEDIUM · (\d+) LOW\*\* "
            r"\((\d+) total"
        ),
        ("aws_critical", "aws_high", "aws_medium", "aws_low", "aws"),
        "post-extension severity distribution",
    ),
]


def main() -> int:
    counts = compute_counts()
    problems: list[str] = []
    verified = 0

    for filename, pattern, expected, what in CHECKS:
        path = REPO_ROOT / filename
        if not path.exists():
            problems.append(f"{filename}: file not found")
            continue
        text = " ".join(path.read_text().split())
        matches = pattern.findall(text)
        if not matches:
            problems.append(
                f"{filename}: could not find the documented count for {what} "
                f"(pattern {pattern.pattern!r}) — was the wording changed? "
                f"Update the doc or tools/check_doc_counts.py CHECKS."
            )
            continue
        expected_values = (
            expected if isinstance(expected, tuple) else (expected,)
        )
        for match in matches:
            # findall yields a string for a single capture group, a tuple otherwise.
            groups = match if isinstance(match, tuple) else (match,)
            actual = tuple(int(g) for g in groups)
            wanted = tuple(counts[k] for k in expected_values)
            if actual != wanted:
                problems.append(
                    f"{filename}: {what} says {actual} but the registries say "
                    f"{wanted} ({', '.join(f'{k}={counts[k]}' for k in expected_values)}). "
                    f"Regenerate the numbers from the registry files — do not "
                    f"hand-type them."
                )
            else:
                verified += 1

    if problems:
        print("DOC COUNT CHECK FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print(
        f"doc counts OK ({verified} verified against the registries: "
        f"AWS {counts['aws']} · Azure {counts['azure']} · GCP {counts['gcp']} · "
        f"Kubernetes {counts['kubernetes']} · total {counts['total']})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
