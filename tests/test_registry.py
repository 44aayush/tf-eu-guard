"""Phase 2 — validate the compliance registry (tf_eu_guard/mapping/registry-{aws,azure,gcp}.yaml).

Hermetic: no Checkov, no network. These tests assert the registry loads, that
every entry is structurally complete, that article references are well-formed,
and that the Phase-1 -> Phase-2 legal-citation corrections have not regressed
(access control = NIS2 21(2)(i), encryption = NIS2 21(2)(h) / GDPR 32(1)(a)).
"""

import re

import pytest

from tf_eu_guard.models import Framework, Severity

# "Art. 21(2)(i)", "Art. 32(1)(a)", the sub-point-less "Art. 21(2)", or a bare
# top-level article like "Art. 44" (GDPR Chapter V transfers have no numbered
# paragraph). The paragraph and sub-point groups are both optional.
ARTICLE_RE = re.compile(r"^Art\. \d+(\(\d+\))?(\([a-z]\))?$")
# Stock Checkov ids ("CKV_AWS_18", "CKV2_AWS_6", "CKV_K8S_16", "CKV2_K8S_6")
# plus tf-eu-guard's custom EU-compliance checks ("EUGUARD_GDPR_001",
# "EUGUARD_NIS2_001").
CHECK_ID_RE = re.compile(r"^(CKV2?_(AWS|AZURE|GCP|K8S)_\d+|EUGUARD_[A-Z0-9]+_\d+)$")


def test_registry_loads_nonempty(registry):
    assert registry, "registry.yaml loaded no mappings"


def test_registry_has_expected_volume(registry):
    # Phase 2 target was 15-20; the shipped registry exceeds it. A floor guards
    # against accidental mass-deletion without being brittle to future growth.
    assert 20 <= len(registry) <= 200, f"unexpected mapping count: {len(registry)}"


def test_check_ids_well_formed(registry):
    bad = sorted(c for c in registry if not CHECK_ID_RE.match(c))
    assert not bad, f"malformed check IDs: {bad}"


def test_every_mapping_is_complete(registry):
    problems: list[str] = []
    for cid, m in registry.items():
        if not m.check_name.strip():
            problems.append(f"{cid}: empty check_name")
        if not m.risk_explanation.strip():
            problems.append(f"{cid}: empty risk")
        if not m.remediation.strip():
            problems.append(f"{cid}: empty remediation")
        if not isinstance(m.severity, Severity):
            problems.append(f"{cid}: bad severity {m.severity!r}")
        if not m.articles:
            problems.append(f"{cid}: no articles")
        for a in m.articles:
            if not isinstance(a.framework, Framework):
                problems.append(f"{cid}: bad framework {a.framework!r}")
            if not ARTICLE_RE.match(a.article):
                problems.append(f"{cid}: malformed article {a.article!r}")
            if not a.title.strip():
                problems.append(f"{cid}: article {a.article} missing title")
    assert not problems, "registry integrity problems:\n" + "\n".join(problems)


def test_no_duplicate_article_refs_within_a_mapping(registry):
    dupes = []
    for cid, m in registry.items():
        refs = [(a.framework, a.article) for a in m.articles]
        if len(refs) != len(set(refs)):
            dupes.append(cid)
    assert not dupes, f"mappings with duplicate article refs: {dupes}"


def test_frameworks_are_only_nis2_and_gdpr(registry):
    seen = {a.framework for m in registry.values() for a in m.articles}
    assert seen <= {Framework.NIS2, Framework.GDPR}, f"unexpected frameworks: {seen}"


def _nis2(mapping) -> set[str]:
    return {a.article for a in mapping.articles if a.framework is Framework.NIS2}


def _gdpr(mapping) -> set[str]:
    return {a.article for a in mapping.articles if a.framework is Framework.GDPR}


@pytest.mark.parametrize("cid", ["CKV_AWS_273", "CKV_AWS_287"])
def test_access_control_maps_to_nis2_letter_i(registry, cid):
    """Access control is Art. 21(2)(i) — NOT the pre-correction (e)."""
    if cid not in registry:
        pytest.skip(f"{cid} not in registry")
    letters = _nis2(registry[cid])
    assert "Art. 21(2)(i)" in letters, f"{cid} NIS2 letters = {letters}"
    assert "Art. 21(2)(e)" not in letters, f"{cid} still uses retired letter (e)"


@pytest.mark.parametrize("cid", ["CKV_AWS_16", "CKV_AWS_145"])
def test_encryption_maps_to_nis2_h_and_gdpr_a(registry, cid):
    """Encryption is NIS2 Art. 21(2)(h) + GDPR Art. 32(1)(a)."""
    if cid not in registry:
        pytest.skip(f"{cid} not in registry")
    assert "Art. 21(2)(h)" in _nis2(registry[cid]), f"{cid} NIS2 = {_nis2(registry[cid])}"
    assert "Art. 32(1)(a)" in _gdpr(registry[cid]), f"{cid} GDPR = {_gdpr(registry[cid])}"


# --- Phase 3: custom EU-specific checks are mapped -----------------------------

@pytest.mark.parametrize("cid", ["EUGUARD_GDPR_001", "EUGUARD_NIS2_001"])
def test_custom_checks_present_and_complete(registry, cid):
    """The Phase 3 custom checks must be mapped so their findings enrich."""
    assert cid in registry, f"{cid} missing from registry.yaml"
    m = registry[cid]
    assert m.check_name.strip()
    assert m.risk_explanation.strip()
    assert m.remediation.strip()
    assert m.articles, f"{cid} has no article mappings"


def test_eu_region_check_maps_to_gdpr_transfers(registry):
    """EU data-residency maps to GDPR Chapter V (Art. 44), not Art. 32."""
    if "EUGUARD_GDPR_001" not in registry:
        pytest.skip("EUGUARD_GDPR_001 not in registry")
    assert "Art. 44" in _gdpr(registry["EUGUARD_GDPR_001"])


def test_eu_region_risk_matches_documented_legal_standard(registry):
    """The registry's finding text must match docs/gdpr-mapping.md: a non-EU
    region is a transfer *requiring justification* under Chapter V — a strong
    signal for review, not an unqualified "violation" (the config alone cannot
    adjudicate lawfulness). Guards the internal-consistency fix (TASKS.md P1 #5)."""
    if "EUGUARD_GDPR_001" not in registry:
        pytest.skip("EUGUARD_GDPR_001 not in registry")
    risk = registry["EUGUARD_GDPR_001"].risk_explanation
    assert "requiring justification" in risk
    assert "not by itself a" in risk and "violation" in risk  # explicit caveat
    assert "data-residency violation" not in risk  # the retired overclaim


def test_hardcoded_secrets_check_maps_to_nis2_secure_dev(registry):
    """Hardcoded secrets map to NIS2 Art. 21(2)(e) (secure development)."""
    if "EUGUARD_NIS2_001" not in registry:
        pytest.skip("EUGUARD_NIS2_001 not in registry")
    assert "Art. 21(2)(e)" in _nis2(registry["EUGUARD_NIS2_001"])


def test_all_registry_files_schema_valid(repo_root):
    """Every registry-*.yaml must pass schema validation (CI regression)."""
    from tf_eu_guard.mapping.loader import validate_all

    counts = validate_all(repo_root / "tf_eu_guard" / "mapping")
    assert counts, "no registry files found"
    assert sum(counts.values()) > 100  # AWS alone has 116


def test_registry_schema_rejects_bad_entry(tmp_path):
    from tf_eu_guard.mapping.loader import (
        RegistryValidationError,
        load_registry_file,
    )

    bad = tmp_path / "registry-bad.yaml"
    bad.write_text(
        "CKV_AWS_999:\n"
        "  check_name: 'x'\n"
        "  articles:\n"
        "    - framework: BOGUS\n"
        "      article: 'Art. 1'\n"
        "      title: 't'\n"
        "  risk: 'r'\n"
        "  remediation: 'x'\n"
        "  severity: SUPERBAD\n"
    )
    try:
        load_registry_file(bad)
        raise AssertionError("expected RegistryValidationError")
    except RegistryValidationError:
        pass


def test_registry_ids_exist_in_checkov(repo_root):
    """Every CKV ID in the registry must exist in the installed Checkov.

    Guards against silent misses: a renamed/removed Checkov check would leave a
    mapping that never enriches anything.
    """
    import checkov.kubernetes.checks.resource.k8s  # noqa: F401
    import checkov.terraform.checks.resource  # noqa: F401
    import yaml
    from checkov.kubernetes.checks.resource.registry import registry as k8s_registry
    from checkov.terraform.checks.data.registry import data_registry
    from checkov.terraform.checks.provider.registry import provider_registry
    from checkov.terraform.checks.resource.registry import resource_registry

    checkov_ids = set()
    for registry in (resource_registry, data_registry, provider_registry, k8s_registry):
        for checks in registry.checks.values():
            for check in checks:
                checkov_ids.add(check.id)

    import json
    from pathlib import Path

    for framework in ("terraform", "kubernetes"):
        graph_dir = Path(checkov.__file__).parent / framework / "checks" / "graph_checks"
        if not graph_dir.is_dir():
            continue
        # Graph checks may sit directly in graph_checks/ (kubernetes) or in
        # per-provider subdirectories (terraform).
        for jf in graph_dir.rglob("*.json"):
            try:
                data = json.loads(jf.read_text())
                checkov_ids.add(data.get("id") or data.get("metadata", {}).get("id"))
            except (json.JSONDecodeError, OSError):
                pass

    mapping_dir = repo_root / "tf_eu_guard" / "mapping"
    registry_ids = set()
    for rf in mapping_dir.glob("registry-*.yaml"):
        registry_ids.update(yaml.safe_load(rf.read_text()))

    ckv_ids = {cid for cid in registry_ids if cid.startswith("CKV")}
    missing = sorted(ckv_ids - checkov_ids)
    assert not missing, (
        f"Registry references Checkov IDs that don't exist in the installed "
        f"Checkov (rename/removal upstream?): {missing}"
    )
