"""Requirement-level regulatory coverage model.

Classifies each requirement of NIS2 Art. 21(2)(a)–(j) and GDPR
Art. 32(1)(a)–(d) (plus GDPR Art. 44, which the custom residency check
maps) into one of five categories, so a user can tell "this requirement
has automated checks" from "this requirement has never been looked at":

- **Automated** — the tool can directly evaluate this from IaC input today
- **Partial** — the technical config provides evidence for only part of
  the requirement
- **Process evidence** — no resource check evidences it; the tool's
  repeatable runs are the evidence
- **Manual** — needs non-IaC evidence (policy, governance, staff
  training, incident-response process) that Terraform/Kubernetes
  manifests structurally can never show
- **Not covered** — no current mapping

The inventory (requirement titles, categories, and rationales) lives in
:mod:`tf_eu_guard.mapping.requirements`; this module holds the model and
computation. The *per-requirement check counts* are computed from the
registries at run time, never hand-typed — see
``tools/generate_coverage_doc.py``, which renders
``docs/regulatory-coverage.md`` from this module.
"""

from collections.abc import Sequence
from dataclasses import dataclass

from tf_eu_guard.mapping.requirements import (
    GDPR_TITLES,
    NIS2_TITLES,
    REQUIREMENTS,
    CoverageCategory,
)
from tf_eu_guard.models import ComplianceMapping, EnrichedFinding, Framework


@dataclass(frozen=True)
class RequirementCoverage:
    """One requirement in the inventory and how well it is covered."""

    framework: Framework
    article: str  # e.g. "21(2)(b)" or "32(1)(a)"
    letter: str  # NIS2 letter ("b") or GDPR key ("32(1)(a)"); == article for NIS2
    title: str
    category: CoverageCategory
    #: Free-text justification; for Manual/Not covered this IS the
    #: documentation of why, for Partial it names what IaC covers vs. not.
    rationale: str
    #: Registry check IDs mapped to this requirement — populated at load
    #: time by :func:`compute_coverage`, never hand-typed.
    checks: tuple[str, ...] = ()

    @property
    def check_count(self) -> int:
        return len(self.checks)

    @property
    def article_label(self) -> str:
        """Full article citation, e.g. 'NIS2 Art. 21(2)(b)'."""
        return f"Art. {self.article}"


def _article_key(framework: Framework, article: str) -> tuple[str, str]:
    """Normalize a registry article string to an inventory key.

    NIS2 "Art. 21(2)(b)" -> ("NIS2", "b"); GDPR "Art. 32(1)(a)" ->
    ("GDPR", "32(1)(a)"); GDPR "Art. 44" -> ("GDPR", "44"). Unknown
    shapes return a key that simply matches nothing in the inventory.
    """
    text = article.removeprefix("Art. ").strip()
    if framework == Framework.NIS2:
        if text.startswith("21(2)(") and text.endswith(")"):
            return (framework.value, text.removeprefix("21(2)(")[0])
        return (framework.value, "")
    return (framework.value, text)


def compute_coverage(
    registry: dict[str, ComplianceMapping],
) -> list[RequirementCoverage]:
    """
    Build the requirement inventory with live per-requirement check IDs.

    The categories and rationales come from :data:`REQUIREMENTS`; the check
    IDs are computed from ``registry`` — every registry mapping citing the
    requirement is attributed to it, so counts can never drift from the
    registries the way the README's hand-typed ones once did.
    """
    by_key: dict[tuple[str, str], list[str]] = {}
    for check_id, mapping in registry.items():
        for article_reference in mapping.articles:
            key = _article_key(article_reference.framework, article_reference.article)
            by_key.setdefault(key, []).append(check_id)

    coverage: list[RequirementCoverage] = []
    for entry in REQUIREMENTS:
        letter: str = entry["letter"]
        if entry["framework"] == Framework.NIS2:
            article_label = f"21(2)({letter})"
            title = NIS2_TITLES[letter]
        else:
            article_label = letter
            title = GDPR_TITLES[letter]
        checks = tuple(sorted(set(by_key.get((entry["framework"].value, letter), []))))
        coverage.append(
            RequirementCoverage(
                framework=entry["framework"],
                article=article_label,
                letter=letter,
                title=title,
                category=entry["category"],
                rationale=entry["rationale"],
                checks=checks,
            )
        )
    return coverage


def coverage_summary(coverage: list[RequirementCoverage]) -> dict[str, int]:
    """Count requirements per category, e.g. for report headlines."""
    summary = {category.value: 0 for category in CoverageCategory}
    for requirement in coverage:
        summary[requirement.category.value] += 1
    return summary


@dataclass(frozen=True)
class RequirementResult:
    """Evidence counts for one requirement: check results (resource x check)."""

    requirement: RequirementCoverage
    ran: int
    passed: int
    failed: int
    suppressed: int
    waived: int = 0


def evaluate_requirements(
    registry: dict[str, ComplianceMapping],
    passed: Sequence[EnrichedFinding],
    failed: Sequence[EnrichedFinding],
    suppressed: Sequence[EnrichedFinding],
    waived: Sequence[EnrichedFinding] = (),
) -> list[RequirementResult]:
    """One row per requirement; each result counts for every requirement its mapping cites.

    Always returns all rows; the CLI filters them by ``--framework``. Articles
    come from ``registry`` (not the findings), so the in-place ``--framework``
    filtering of finding objects cannot change the counts.
    """
    buckets = (passed, failed, suppressed, waived)
    counts: dict[tuple[str, str], list[int]] = {}
    for index, results in enumerate(buckets):
        for finding in results:
            mapping = registry.get(finding.check_id)
            keys = {
                _article_key(a.framework, a.article) for a in (mapping.articles if mapping else [])
            }
            for key in keys:
                counts.setdefault(key, [0, 0, 0, 0])[index] += 1
    rows = []
    for requirement in compute_coverage(registry):
        p, f, s, w = counts.get((requirement.framework.value, requirement.letter), [0, 0, 0, 0])
        rows.append(RequirementResult(requirement, p + f + s + w, p, f, s, w))
    return rows
