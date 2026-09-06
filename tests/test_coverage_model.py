"""Tests for the requirement-level coverage model (tf_eu_guard/mapping/coverage.py)
and its generated doc (tools/generate_coverage_doc.py).

The coverage model exists so a user can tell "NIS2 Art. 21(2)(h) has a
mapped check" from "NIS2 Art. 21(2)(a) has never been looked at" — every
unaddressed requirement otherwise looks identical (silently absent) to a
covered one. These tests pin the four-category classification and,
critically, that per-requirement check counts are computed from the live
registries rather than hand-typed (the README's mapping counts drifted
once that way).
"""

import sys
from pathlib import Path

from tf_eu_guard.mapping.coverage import (
    NIS2_TITLES,
    REQUIREMENTS,
    CoverageCategory,
    compute_coverage,
    coverage_summary,
)
from tf_eu_guard.models import Framework

TOOLS_DIR = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import generate_coverage_doc  # noqa: E402

# --- Inventory completeness -------------------------------------------------


def test_inventory_covers_all_nis2_21_2_letters():
    """NIS2 Art. 21(2)(a)–(j) — every letter, no more, no less."""
    letters = {e["letter"] for e in REQUIREMENTS if e["framework"] == Framework.NIS2}
    assert letters == set("abcdefghij")


def test_inventory_covers_gdpr_32_1_and_44():
    """GDPR Art. 32(1)(a)–(d) plus Art. 44 (the custom residency check maps it)."""
    keys = {e["letter"] for e in REQUIREMENTS if e["framework"] == Framework.GDPR}
    assert keys == {"32(1)(a)", "32(1)(b)", "32(1)(c)", "32(1)(d)", "44"}


def test_every_requirement_is_classified():
    """No entry may skip the classification — 'unknown' is what the model exists to kill."""
    for entry in REQUIREMENTS:
        assert isinstance(entry["category"], CoverageCategory)
        assert entry["rationale"].strip()


# --- Classification against the live registries ----------------------------


def test_no_automated_requirement_without_checks(registry):
    """An 'Automated' claim must be backed by registry-mapped checks —
    otherwise the doc overclaims exactly the way the model exists to prevent."""
    coverage = compute_coverage(registry)
    for requirement in coverage:
        if requirement.category == CoverageCategory.AUTOMATED:
            assert requirement.checks, (
                f"{requirement.article} claims Automated but has no mapped checks"
            )


def test_manual_requirements_have_no_mapped_checks(registry):
    """'Manual' means Terraform/K8s manifests structurally can never show it —
    if a check is actually mapped there, the classification is wrong, not the registry."""
    coverage = compute_coverage(registry)
    for requirement in coverage:
        if requirement.category == CoverageCategory.MANUAL:
            assert not requirement.checks, (
                f"{requirement.article} is classified Manual but has mapped "
                f"checks: {requirement.checks}"
            )


def test_not_covered_category_is_unused_but_supported(registry):
    """Current inventory maps checks to everything except the two documented
    Manual requirements — i.e. no requirement is silently 'not covered'.
    The category itself must stay a valid, selectable value."""
    coverage = compute_coverage(registry)
    assert all(r.category != CoverageCategory.NOT_COVERED for r in coverage)
    assert CoverageCategory("not covered") == CoverageCategory.NOT_COVERED


def test_check_counts_computed_from_live_registry(registry):
    """The counts are registry-derived, not hand-typed: adding a temporary
    mapping changes the attributed check set."""
    from tf_eu_guard.models import ArticleReference, ComplianceMapping, Severity

    coverage = compute_coverage(registry)
    by_article = {r.article: r for r in coverage}
    h = by_article["21(2)(h)"]
    assert h.check_count > 0

    registry_extra = dict(registry)
    registry_extra["CKV_TEST_EXTRA"] = ComplianceMapping(
        check_id="CKV_TEST_EXTRA",
        check_name="test",
        articles=[
            ArticleReference(
                framework=Framework.NIS2, article="Art. 21(2)(h)", title="x"
            )
        ],
        risk_explanation="r",
        remediation="r",
        severity=Severity.HIGH,
    )
    extra_coverage = compute_coverage(registry_extra)
    extra_h = next(r for r in extra_coverage if r.article == "21(2)(h)")
    assert extra_h.check_count == h.check_count + 1
    assert "CKV_TEST_EXTRA" in extra_h.checks
    # the real registry is untouched
    assert "CKV_TEST_EXTRA" not in registry


def test_every_registry_article_is_attributed(registry):
    """Every article cited in the registries must be attributed to some
    requirement — an unmapped article string would silently vanish,
    recreating the problem this model fixes."""
    from tf_eu_guard.mapping.coverage import _article_key

    inventory_keys = {(e["framework"].value, e["letter"]) for e in REQUIREMENTS}
    for mapping in registry.values():
        for article in mapping.articles:
            key = _article_key(article.framework, article.article)
            assert key in inventory_keys, (
                f"{mapping.check_id} cites {article.framework.value} "
                f"'{article.article}' which is not in the requirement inventory"
            )


def test_coverage_summary_counts_every_requirement(registry):
    coverage = compute_coverage(registry)
    summary = coverage_summary(coverage)
    assert sum(summary.values()) == len(coverage) == len(REQUIREMENTS)


# --- Generated doc -----------------------------------------------------------


def test_doc_generator_renders_every_requirement(registry):
    rendered = generate_coverage_doc.render_doc()
    coverage = compute_coverage(registry)
    for requirement in coverage:
        assert f"Art. {requirement.article}" in rendered
        assert requirement.title in rendered
        assert requirement.rationale in rendered


def test_committed_doc_is_in_sync_with_registries():
    """CI's --check, as a test: the committed docs/regulatory-coverage.md must
    match what the registries generate (the drift guard, same shape as
    tools/check_doc_counts.py's)."""
    assert generate_coverage_doc.main_check() == 0


def test_doc_check_detects_drift(registry, tmp_path, monkeypatch, capsys):
    """A doctored committed doc must fail the check — the guard actually guards."""
    doc = generate_coverage_doc.DOC_PATH
    original = doc.read_text()
    monkeypatch.setattr(
        generate_coverage_doc.Path, "read_text",
        lambda self, *a, **kw: original.replace("15 requirements", "99 requirements")
        if self == doc else Path.read_text(self, *a, **kw),
    )
    assert generate_coverage_doc.main_check() == 1
    assert "out of sync" in capsys.readouterr().err


def test_doc_check_fails_when_doc_missing(tmp_path, capsys, monkeypatch):
    """No doc file -> explicit failure telling you to generate it."""
    monkeypatch.setattr(
        generate_coverage_doc, "DOC_PATH", tmp_path / "missing.md"
    )
    assert generate_coverage_doc.main_check() == 1
    assert "does not exist" in capsys.readouterr().err


def test_nis2_titles_are_canonical():
    """One canonical title per letter; letter set matches the NIS2 directive."""
    assert set(NIS2_TITLES) == set("abcdefghij")
    assert all(t.strip() for t in NIS2_TITLES.values())
