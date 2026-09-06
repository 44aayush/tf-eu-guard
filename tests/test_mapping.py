"""Phase 2 — validate enrichment (tf_eu_guard.mapping.loader.enrich_findings).

Hermetic: uses synthetic Checkov-shaped findings, no Checkov invocation. Covers
the core contract: unmapped findings are dropped from the enriched list, mapped
findings gain the registry's articles/risk/remediation/severity, and the Checkov
``check_name`` (not the registry's) is preserved on the enriched finding.
"""

from tf_eu_guard.mapping.loader import enrich_findings, split_findings
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


# --- split_findings: unmapped findings are kept aside, not dropped ---------------


def test_split_findings_keeps_unmapped_aside(registry, sample_finding):
    """The regression this guards: an unmapped Checkov finding must come back
    from split_findings (so reports can surface it), even though
    enrich_findings alone would drop it."""
    mapped_cid = next(iter(registry))
    unmapped = sample_finding("CKV_AWS_DOES_NOT_EXIST_999")
    enriched, unmapped_out = split_findings(
        [sample_finding(mapped_cid), unmapped], registry
    )
    assert [f.check_id for f in enriched] == [mapped_cid]
    assert unmapped_out == [unmapped]


def test_split_findings_preserves_unmapped_fields(registry, sample_finding):
    """The raw Checkov dict survives untouched — resource, file, lines — so a
    caller can render it without re-running Checkov."""
    raw = sample_finding(
        "CKV_AWS_10", resource="aws_iam_account_password_policy.weak",
        file_path="/main.tf", file_line_range=[3, 12],
    )
    _, unmapped = split_findings([raw], registry)
    assert unmapped == [raw]
    assert unmapped[0]["resource"] == "aws_iam_account_password_policy.weak"
    assert unmapped[0]["file_line_range"] == [3, 12]


def test_split_findings_empty_input(registry):
    assert split_findings([], registry) == ([], [])


def test_split_findings_partitions_every_finding(registry, sample_finding):
    """No finding is lost or duplicated: mapped + unmapped == input count."""
    known = list(registry)[:3]
    findings = [sample_finding(c) for c in known] + [
        sample_finding("CKV_AWS_UNMAPPED_1"), sample_finding("CKV_AWS_UNMAPPED_2")
    ]
    enriched, unmapped = split_findings(findings, registry)
    assert len(enriched) + len(unmapped) == len(findings)
    assert all(isinstance(f, EnrichedFinding) for f in enriched)
    assert all(isinstance(f, dict) for f in unmapped)
