#!/usr/bin/env python3
"""Generate docs/regulatory-coverage.md from the mapping registries.

Requirement-level coverage: classifies each requirement of NIS2 Art. 21(2)
and GDPR Art. 32(1)/44 as Automated / Partial / Manual / Not covered, so a
reader can tell "NIS2 Art. 21(2)(h) has automated checks" from "NIS2
Art. 21(2)(a) needs organisational evidence this tool cannot see" — every
unaddressed requirement otherwise looks identical (silently absent) to a
covered one.

The categories and rationales are authored in
``tf_eu_guard/mapping/coverage.py`` (they encode what IaC can structurally
show — a human judgement). The per-requirement check counts and IDs are
computed from ``registry-*.yaml`` at generation time, never hand-typed, so
they cannot drift the way the README's mapping counts once did. The drift
guard is the generator itself: run with ``--check`` to re-render and fail
if the committed file differs from what the registries produce.

Run standalone (CI does):

    python3 tools/generate_coverage_doc.py            # regenerate in place
    python3 tools/generate_coverage_doc.py --check    # CI drift check

Exit codes: 0 = generated / in sync, 1 = out of sync (--check) or a
registry/inventory error.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tf_eu_guard.mapping.coverage import (  # noqa: E402
    CoverageCategory,
    compute_coverage,
    coverage_summary,
)
from tf_eu_guard.mapping.loader import load_registry  # noqa: E402

DOC_PATH = REPO_ROOT / "docs" / "regulatory-coverage.md"

CATEGORY_BADGES = {
    CoverageCategory.AUTOMATED: "✅ **Automated**",
    CoverageCategory.PARTIAL: "◐ **Partial**",
    CoverageCategory.MANUAL: "👤 **Manual**",
    CoverageCategory.NOT_COVERED: "❌ **Not covered**",
}

CATEGORY_BLURBS = {
    CoverageCategory.AUTOMATED: (
        "The tool can directly evaluate this from IaC input today."
    ),
    CoverageCategory.PARTIAL: (
        "The technical config provides evidence for only part of the "
        "requirement; the rest needs non-IaC evidence."
    ),
    CoverageCategory.MANUAL: (
        "Needs non-IaC evidence (policy, governance, staff training, "
        "incident-response process) that Terraform/Kubernetes manifests "
        "structurally can never show. Listed here so it is visibly *not "
        "ignored* — an explicit 'we cannot see this' is more credible than "
        "silence."
    ),
    CoverageCategory.NOT_COVERED: "No current mapping.",
}


def _check_cell(requirement) -> str:
    """The checks column: the count (IDs live in the per-requirement
    sections below, so a 90-check row doesn't render as a wall of IDs)."""
    if requirement.check_count:
        return f"**{requirement.check_count}**"
    return "—"


def render_doc() -> str:
    registry = load_registry(REPO_ROOT / "tf_eu_guard" / "mapping")
    coverage = compute_coverage(registry)
    summary = coverage_summary(coverage)

    lines: list[str] = []
    lines.append("# Regulatory Coverage — NIS2 Art. 21(2) & GDPR Art. 32(1)/44")
    lines.append("")
    lines.append(
        "> **Generated file** — rendered by `tools/generate_coverage_doc.py` from "
        "the mapping registries and the requirement inventory in "
        "`tf_eu_guard/mapping/coverage.py`. Do not edit by hand; CI "
        "(via `--check`) fails if this file drifts from the registries."
    )
    lines.append("")
    lines.append(
        "Coverage here is classified **by requirement, not by mapped-check "
        "count**. Every unaddressed requirement otherwise looks identical — "
        "silently absent — to a covered one. Four categories:"
    )
    lines.append("")
    for category in CoverageCategory:
        lines.append(f"- {CATEGORY_BADGES[category]} — {CATEGORY_BLURBS[category]}")
    lines.append("")

    summary_bits = []
    if summary[CoverageCategory.AUTOMATED.value]:
        summary_bits.append(
            f"{summary[CoverageCategory.AUTOMATED.value]} automated"
        )
    if summary[CoverageCategory.PARTIAL.value]:
        summary_bits.append(f"{summary[CoverageCategory.PARTIAL.value]} partial")
    if summary[CoverageCategory.MANUAL.value]:
        summary_bits.append(f"{summary[CoverageCategory.MANUAL.value]} manual")
    if summary[CoverageCategory.NOT_COVERED.value]:
        summary_bits.append(
            f"{summary[CoverageCategory.NOT_COVERED.value]} not covered"
        )
    lines.append(
        f"**Summary: {len(coverage)} requirements inventoried — "
        f"{' · '.join(summary_bits)}.**"
    )
    lines.append("")

    for framework, heading in (
        ("NIS2", "## NIS2 — Directive (EU) 2022/2555, Art. 21(2)"),
        ("GDPR", "## GDPR — Regulation (EU) 2016/679, Art. 32(1) & Art. 44"),
    ):
        lines.append(heading)
        lines.append("")
        lines.append("| Requirement | Coverage | Mapped checks |")
        lines.append("|-------------|----------|---------------|")
        for requirement in coverage:
            if requirement.framework.value != framework:
                continue
            lines.append(
                f"| **Art. {requirement.article}** — {requirement.title} "
                f"| {CATEGORY_BADGES[requirement.category]} "
                f"| {_check_cell(requirement)} |"
            )
        lines.append("")

        for requirement in coverage:
            if requirement.framework.value != framework:
                continue
            lines.append(f"### {requirement.framework.value} Art. {requirement.article} — {requirement.title}")
            lines.append("")
            lines.append(f"{CATEGORY_BADGES[requirement.category]}")
            lines.append("")
            lines.append(requirement.rationale)
            if requirement.checks:
                lines.append("")
                checks = ", ".join(f"`{c}`" for c in requirement.checks)
                lines.append(
                    f"Mapped checks ({requirement.check_count}): {checks}."
                )
            lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "Related: [`docs/nis2-mapping.md`](nis2-mapping.md) and "
        "[`docs/gdpr-mapping.md`](gdpr-mapping.md) give the per-check "
        "evidence and limitations; [`docs/check-mapping-table.md`](check-mapping-table.md) "
        "is the full check-level matrix. Guiding principle: this project is "
        "measured by mapping *quality*, tracked honestly here — automated vs. "
        "partial vs. manual vs. not covered — not by a single 'N checks mapped' "
        "headline number."
    )
    lines.append("")
    return "\n".join(lines)


def main(check_only: bool = False) -> int:
    check_only = check_only or "--check" in sys.argv[1:]
    rendered = render_doc()

    if check_only:
        if not DOC_PATH.exists():
            print(
                f"COVERAGE DOC CHECK FAILED: {DOC_PATH} does not exist — "
                f"run `python3 tools/generate_coverage_doc.py` to generate it.",
                file=sys.stderr,
            )
            return 1
        committed = DOC_PATH.read_text()
        if committed != rendered:
            print(
                "COVERAGE DOC CHECK FAILED: docs/regulatory-coverage.md is out "
                "of sync with the registries (or the requirement inventory "
                "changed). Regenerate it: "
                "python3 tools/generate_coverage_doc.py",
                file=sys.stderr,
            )
            return 1
        print("coverage doc OK (docs/regulatory-coverage.md matches the registries)")
        return 0

    DOC_PATH.write_text(rendered)
    print(f"wrote {DOC_PATH}")
    return 0


#: Alias used by the tests — the CI drift check as a callable.
main_check = lambda: main(check_only=True)  # noqa: E731


if __name__ == "__main__":
    sys.exit(main())
