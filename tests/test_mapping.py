"""Phase 2 — validate enrichment (tf_eu_guard.mapping.loader.enrich_findings).

Hermetic: uses synthetic Checkov-shaped findings, no Checkov invocation. Covers
the core contract: unmapped findings are dropped, mapped findings gain the
registry's articles/risk/remediation/severity, and the Checkov ``check_name``
(not the registry's) is preserved on the enriched finding.
"""

from tf_eu_guard.mapping.loader import enrich_findings
from tf_eu_guard.models import EnrichedFinding, Framework


def test_unmapped_findings_are_dropped(registry, sample_finding):
    out = enrich_findings([sample_finding("CKV_AWS_DOES_NOT_EXIST_999")], registry)
    assert out == []


def test_empty_input_yields_empty(registry):
    assert enrich_findings([], registry) == []


def test_mapped_finding_is_enriched(registry, sample_finding):
    cid = "CKV_AWS_287" if "CKV_AWS_287" in registry else next(iter(registry))
    out = enrich_findings([sample_finding(cid)], registry)
    assert len(out) == 1
    f = out[0]
    assert isinstance(f, EnrichedFinding)
    assert f.check_id == cid
    assert f.articles, "no articles attached"
    assert f.severity == registry[cid].severity
    assert f.risk_explanation == registry[cid].risk_explanation
    assert f.remediation == registry[cid].remediation


def test_enrichment_keeps_checkov_check_name(registry, sample_finding):
    """The enriched finding must show Checkov's name, not the registry's."""
    cid = next(iter(registry))
    out = enrich_findings([sample_finding(cid, check_name="NAME_FROM_CHECKOV")], registry)
    assert out[0].check_name == "NAME_FROM_CHECKOV"


def test_only_registry_ids_survive_mixed_input(registry, sample_finding):
    known = list(registry)[:5]
    findings = [sample_finding(c) for c in known] + [sample_finding("CKV_AWS_UNMAPPED_1")]
    out = enrich_findings(findings, registry)
    assert len(out) == len(known)
    assert all(f.check_id in registry for f in out)


def test_frameworks_property_reflects_articles(registry, sample_finding):
    cid = "CKV_AWS_287" if "CKV_AWS_287" in registry else next(iter(registry))
    out = enrich_findings([sample_finding(cid)], registry)
    expected = {a.framework for a in registry[cid].articles}
    assert out[0].frameworks == expected
    assert out[0].frameworks <= {Framework.NIS2, Framework.GDPR}
