"""Phase 2 — validate the compliance registry (tf_eu_guard/mapping/registry-{aws,azure,gcp}.yaml).

Hermetic: no Checkov, no network. These tests assert the registry loads, that
every entry is structurally complete, that article references are well-formed,
and that the Phase-1 -> Phase-2 legal-citation corrections have not regressed
(access control = NIS2 21(2)(i), encryption = NIS2 21(2)(h) / GDPR 32(1)(a)).
"""

import json
import re
from pathlib import Path

import checkov
import checkov.kubernetes.checks.resource.k8s  # noqa: F401
import checkov.terraform.checks.resource  # noqa: F401
import pytest
import yaml
from checkov.kubernetes.checks.resource.registry import registry as k8s_registry
from checkov.terraform.checks.data.registry import data_registry
from checkov.terraform.checks.provider.registry import provider_registry
from checkov.terraform.checks.resource.registry import resource_registry

from tf_eu_guard.checkov_runner import extract_failed_checks, load_checkov_json
from tf_eu_guard.mapping.loader import (
    RegistryValidationError,
    load_registry,
    load_registry_file,
    validate_all,
)
from tf_eu_guard.mapping.requirements import ARTICLE_TITLES
from tf_eu_guard.models import Framework, Severity

# "Art. 21(2)(i)", "Art. 32(1)(a)", the sub-point-less "Art. 21(2)", or a bare
# top-level article like "Art. 44" (GDPR Chapter V transfers have no numbered
# paragraph). Project policy references use the same registry article field but
# are explicitly outside the regulatory article inventory.
ARTICLE_RE = re.compile(r"^(?:Art\. \d+(\(\d+\))?(\([a-z]\))?|Policy [A-Za-z0-9_.-]+)$")
# Stock Checkov ids ("CKV_AWS_18", "CKV2_AWS_6", "CKV_K8S_16", "CKV2_K8S_6")
# plus tf-eu-guard's custom EU-compliance checks ("EUGUARD_GDPR_001",
# "EUGUARD_GDPR_002", "EUGUARD_NIS2_001").
CHECK_ID_RE = re.compile(r"^(CKV2?_(AWS|AZURE|GCP|K8S)_\d+|EUGUARD_[A-Z0-9]+_\d+)$")


def test_registry_loads_nonempty(registry):
    assert registry, "registry.yaml loaded no mappings"


def test_registry_has_expected_volume(registry):
    # Phase 2 target was 15-20; the shipped registry exceeds it. A floor guards
    # against accidental mass-deletion without being brittle to future growth.
    assert 20 <= len(registry) <= 300, f"unexpected mapping count: {len(registry)}"


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


def test_frameworks_include_regulations_and_project_policy(registry):
    seen = {a.framework for m in registry.values() for a in m.articles}
    assert seen <= {Framework.NIS2, Framework.GDPR, Framework.POLICY}, (
        f"unexpected frameworks: {seen}"
    )
    assert Framework.POLICY in seen, "the EUSC sovereignty mapping must stay policy-scoped"


def test_registry_titles_match_canonical_article_table(repo_root):
    """Every registry uses one authoritative legal title per article."""
    seen: dict[tuple[str, str], set[str]] = {}
    for path in sorted((repo_root / "tf_eu_guard" / "mapping").glob("registry-*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for check_id, entry in raw.items():
            for article in entry["articles"]:
                key = (article["framework"], article["article"])
                seen.setdefault(key, set()).add(article["title"])
                canonical = ARTICLE_TITLES[(Framework(article["framework"]), article["article"])]
                assert article["title"] == canonical, (
                    f"{path.name}:{check_id} has non-canonical title"
                )
    assert all(len(titles) == 1 for titles in seen.values())


def test_registry_risk_text_does_not_make_unsupported_legal_conclusions(repo_root):
    pattern = re.compile(
        r"(?i)(violates?|contrary to|direct (?:GDPR|NIS2)|failure under|defeats|squarely against)"
    )
    for path in sorted((repo_root / "tf_eu_guard" / "mapping").glob("registry-*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for check_id, entry in raw.items():
            text = entry.get("risk", "")
            for match in pattern.finditer(text):
                window = text[max(0, match.start() - 40) : match.end() + 40]
                assert "Art." not in window, (
                    f"unsupported legal wording in {path.name}:{check_id}: {window!r}"
                )


def test_registry_risk_citations_are_declared_in_articles(repo_root):
    """Risk text must not cite a framework/article absent from the mapping."""
    citation = re.compile(r"\b(NIS2|GDPR)\s+(Art\. \d+(?:\(\d+\))?(?:\([a-z]\))?)")
    for path in sorted((repo_root / "tf_eu_guard" / "mapping").glob("registry-*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for check_id, entry in raw.items():
            declared = {(article["framework"], article["article"]) for article in entry["articles"]}
            cited = set(citation.findall(entry.get("risk", "")))
            assert cited <= declared, (
                f"undeclared risk citation in {path.name}:{check_id}: {sorted(cited - declared)}"
            )


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


@pytest.mark.parametrize(
    "cid",
    ["EUGUARD_GDPR_001", "EUGUARD_GDPR_002", "EUGUARD_NIS2_001"],
)
def test_custom_checks_present_and_complete(registry, cid):
    """The Phase 3 custom checks must be mapped so their findings enrich."""
    assert cid in registry, f"{cid} missing from registry.yaml"
    m = registry[cid]
    assert m.check_name.strip()
    assert m.risk_explanation.strip()
    assert m.remediation.strip()
    assert m.articles, f"{cid} has no article mappings"


def test_region_checks_separate_sovereignty_policy_from_transfers(registry):
    """Commercial EU policy failures must not be labelled as Chapter V transfers."""
    assert _gdpr(registry["EUGUARD_GDPR_001"]) == set()
    assert {
        (article.framework, article.article) for article in registry["EUGUARD_GDPR_001"].articles
    } == {(Framework.POLICY, "Policy EUSC-001")}
    assert _gdpr(registry["EUGUARD_GDPR_002"]) == {"Art. 44"}


def test_canonical_titles_cover_corrected_articles(registry):
    assert registry["CKV_AWS_163"].articles
    gdpr_b = [
        a
        for a in registry["CKV_AWS_163"].articles
        if a.framework is Framework.GDPR and a.article == "Art. 32(1)(b)"
    ]
    assert gdpr_b and gdpr_b[0].title == ARTICLE_TITLES[(Framework.GDPR, "Art. 32(1)(b)")]
    nis2_g = [
        a
        for a in registry.values()
        for a in a.articles
        if a.framework is Framework.NIS2 and a.article == "Art. 21(2)(g)"
    ]
    assert nis2_g and {a.title for a in nis2_g} == {
        ARTICLE_TITLES[(Framework.NIS2, "Art. 21(2)(g)")]
    }


def test_transfer_review_risk_matches_documented_legal_standard(registry):
    """The Art. 44 mapping remains a hedged review signal, not a legal verdict."""
    policy_risk = registry["EUGUARD_GDPR_001"].risk_explanation
    assert "project-policy deviation" in policy_risk
    assert "GDPR legal conclusion" in policy_risk
    assert "GDPR Art. 44" not in policy_risk

    transfer_risk = registry["EUGUARD_GDPR_002"].risk_explanation
    assert "may involve a third-country transfer" in transfer_risk
    assert "not a definitive legal conclusion" in transfer_risk
    assert "violation" not in transfer_risk


def test_kubernetes_secret_mapping_is_kubernetes_specific(registry):
    remediation = registry["EUGUARD_NIS2_002"].remediation
    assert "secretKeyRef" in remediation
    assert "aws_" not in remediation
    assert 'resource "' not in remediation


def test_remediations_match_eusc_region_policy(registry):
    assert "in-policy region" in registry["CKV_AWS_144"].remediation
    assert 'region = "eusc-de-east-1"' in registry["CKV_AWS_41"].remediation


@pytest.mark.parametrize("cid", ["CKV_AWS_24", "CKV_AWS_25", "CKV_AWS_260", "CKV_AWS_382"])
def test_security_group_remediation_covers_both_ip_families(registry, cid):
    remediation = registry[cid].remediation
    assert 'resource "aws_security_group"' in remediation
    assert "cidr_blocks" in remediation
    assert "ipv6_cidr_blocks" in remediation
    assert "0.0.0.0/0" in remediation
    assert "::/0" in remediation


def test_ecs_embedded_json_uses_provider_api_key(registry):
    remediation = registry["CKV_AWS_336"].remediation
    assert 'resource "aws_ecs_task_definition"' in remediation
    assert "container_definitions = jsonencode" in remediation
    assert "readonlyRootFilesystem = true" in remediation
    assert "readonly_root_filesystem" not in remediation


def test_api_gateway_certificate_remediation_names_trust_direction(registry):
    mapping = registry["CKV2_AWS_51"]
    text = mapping.risk_explanation + "\n" + mapping.remediation
    assert 'resource "aws_api_gateway_client_certificate"' in text
    assert 'resource "aws_api_gateway_stage"' in text
    assert "integration backend" in text
    assert "incoming caller mTLS" in text
    assert "mutual_tls_authentication" in text
    assert "truststore_uri" in text


def test_k8s_read_only_filesystem_declares_gdpr_article(registry):
    mapping = registry["CKV_K8S_22"]
    assert (Framework.GDPR, "Art. 32(1)(b)") in {
        (article.framework, article.article) for article in mapping.articles
    }


def test_hardcoded_secrets_check_maps_to_nis2_secure_dev(registry):
    """Hardcoded secrets map to NIS2 Art. 21(2)(e) (secure development)."""
    if "EUGUARD_NIS2_001" not in registry:
        pytest.skip("EUGUARD_NIS2_001 not in registry")
    assert "Art. 21(2)(e)" in _nis2(registry["EUGUARD_NIS2_001"])


def test_all_registry_files_schema_valid(repo_root):
    """Every registry-*.yaml must pass schema validation (CI regression)."""
    counts = validate_all(repo_root / "tf_eu_guard" / "mapping")
    assert counts, "no registry files found"
    assert sum(counts.values()) > 100  # AWS alone has 116


def test_registry_schema_rejects_bad_entry(tmp_path):
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


def test_runtime_registry_requires_all_expected_namespaces(tmp_path):
    mapping_dir = tmp_path / "mapping"
    mapping_dir.mkdir()
    (mapping_dir / "registry-aws.yaml").write_text("{}\n")

    with pytest.raises(RegistryValidationError, match="no entries found"):
        load_registry(mapping_dir)


def test_runtime_registry_rejects_missing_path(tmp_path):
    with pytest.raises(RegistryValidationError, match="does not exist"):
        load_registry(tmp_path / "missing-mapping")


def test_runtime_registry_rejects_missing_namespace(tmp_path, repo_root):
    mapping_dir = tmp_path / "mapping"
    mapping_dir.mkdir()
    source = repo_root / "tf_eu_guard" / "mapping"
    for namespace in ("aws", "azure", "gcp"):
        (mapping_dir / f"registry-{namespace}.yaml").write_text(
            (source / f"registry-{namespace}.yaml").read_text(encoding="utf-8"),
            encoding="utf-8",
        )

    with pytest.raises(RegistryValidationError, match="kubernetes"):
        load_registry(mapping_dir)


@pytest.mark.parametrize(
    ("content", "where"),
    [
        ("- one\n- two\n", r"registry-bad.yaml"),
        ("CKV_X:\n", r"registry-bad.yaml:CKV_X"),
        ("CKV_X: string\n", r"registry-bad.yaml:CKV_X"),
        (
            "CKV_X:\n  check_name: x\n  articles: [null]\n  risk: r\n  remediation: fix\n  severity: LOW\n",
            r"registry-bad.yaml:CKV_X",
        ),
        (
            "CKV_X:\n  check_name: x\n  articles:\n    - framework: GDPR\n      article: lol\n      title: t\n  risk: r\n  remediation: fix\n  severity: LOW\n",
            r"registry-bad.yaml:CKV_X",
        ),
        (
            "CKV_X:\n  check_name: [x]\n  articles: []\n  risk: r\n  remediation: fix\n  severity: LOW\n",
            r"registry-bad.yaml:CKV_X",
        ),
    ],
)
def test_registry_shape_errors_are_registry_validation_errors(tmp_path, content, where):
    bad = tmp_path / "registry-bad.yaml"
    bad.write_text(content)
    with pytest.raises(RegistryValidationError, match=where):
        load_registry_file(bad)


def test_registry_rejects_within_file_duplicate_check_id(tmp_path):
    """The same check_id twice in ONE file must fail loudly.

    ``yaml.safe_load`` silently keeps only the second definition — the
    duplicate collapses before any validation code runs, so the cross-file
    duplicate guard can never see it. The custom loader must catch it.
    """
    entry = (
        "  check_name: '{name}'\n"
        "  articles:\n"
        "    - framework: GDPR\n"
        "      article: 'Art. 32'\n"
        "      title: 't'\n"
        "  risk: 'r'\n"
        "  remediation: 'x'\n"
        "  severity: LOW\n"
    )
    dup = tmp_path / "registry-dup.yaml"
    dup.write_text(
        "CKV_AWS_1:\n" + entry.format(name="first") + "CKV_AWS_1:\n" + entry.format(name="second")
    )
    with pytest.raises(RegistryValidationError, match=r"CKV_AWS_1.*line 10"):
        load_registry_file(dup)


@pytest.mark.parametrize(
    "content",
    [
        "[foo, bar]: value\n",
        "42: value\n",
        "{foo: bar}: value\n",
    ],
    ids=["list", "integer", "mapping"],
)
def test_registry_rejects_non_string_mapping_keys_with_context(tmp_path, content):
    """Invalid YAML mapping keys become contextual registry errors, not TypeError."""
    bad = tmp_path / "registry-bad.yaml"
    bad.write_text(content)

    with pytest.raises(
        RegistryValidationError,
        match=r"registry-bad\.yaml: .*non-string mapping key.*line 1",
    ):
        load_registry_file(bad)


def test_registry_ids_exist_in_checkov(repo_root):
    """Every CKV ID in the registry must exist in the installed Checkov.

    Guards against silent misses: a renamed/removed Checkov check would leave a
    mapping that never enriches anything.
    """
    checkov_ids = set()
    for registry in (resource_registry, data_registry, provider_registry, k8s_registry):
        for checks in registry.checks.values():
            for check in checks:
                checkov_ids.add(check.id)

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


# --- end2end stack: every check that fires is mapped (zero unmapped) ------------
# The claim "a scan of examples/end2end/ produces zero unmapped findings" is
# repeated across the docs. This test makes it executable from a committed
# real-Checkov capture, so a registry edit that drops an end2end check fails
# CI instead of silently degrading that scan to unmapped.

END2END_FIXTURE = "tests/fixtures/checkov-end2end-tf.json"
# Raw Checkov output for the stack. tf-eu-guard's own scan adds its custom
# EUGUARD_* checks on top of the stock findings; the exact custom count is
# asserted by the live CLI fixture test rather than duplicated in this comment.


def test_end2end_findings_are_all_mapped(repo_root, registry):
    """Every stock Checkov check firing on the end2end stack has a registry entry.

    Hermetic: reads the committed Checkov capture rather than running Checkov
    (the capture is regenerated by ``tools/smoke_check.py`` / CI, which runs
    the real scan and checks the same property against the 295 baseline).
    """
    capture = repo_root / END2END_FIXTURE
    if not capture.exists():
        pytest.skip(f"{END2END_FIXTURE} not present — run tools/smoke_check.py")

    findings = extract_failed_checks(load_checkov_json(capture))
    assert findings, "the end2end capture contains no failed checks (stale fixture?)"

    unmapped = sorted({f["check_id"] for f in findings} - set(registry))
    assert not unmapped, (
        f"checks firing on examples/end2end/ have no registry mapping — a scan "
        f"now reports them as unmapped: {unmapped}"
    )


# --- Registry expansion: CloudTrail / CodeBuild / ECS / ElastiCache / Aurora ---
# These IDs were originally confirmed from the historical Checkov 3.3.13
# capture of the corresponding examples/end2end/*.tf fixtures, then authored.
# Current runtime verification uses live Checkov 3.3.29 scans. The tests guard
# the mapping (not the capture): if an entry is removed, the finding goes back
# to being unmapped.

EXPANSION_IDS = {
    # cloudtrail.tf
    "CKV_AWS_67",
    "CKV_AWS_36",
    "CKV_AWS_35",
    "CKV_AWS_252",
    "CKV2_AWS_10",
    # codebuild.tf
    "CKV_AWS_316",
    "CKV_AWS_147",
    "CKV_AWS_314",
    # ecs.tf
    "CKV_AWS_333",
    "CKV_AWS_65",
    "CKV_AWS_223",
    "CKV_AWS_224",
    "CKV_AWS_332",
    "CKV_AWS_336",
    "CKV_AWS_249",
    # elasticache.tf
    "CKV_AWS_29",
    "CKV_AWS_30",
    "CKV_AWS_31",
    "CKV_AWS_191",
    "CKV2_AWS_50",
    # rds-cluster.tf (all pre-existing)
    "CKV_AWS_96",
    "CKV_AWS_139",
    "CKV_AWS_313",
    "CKV_AWS_324",
    "CKV_AWS_325",
    "CKV_AWS_326",
    "CKV_AWS_327",
    "CKV_AWS_162",
    "CKV2_AWS_8",
    # redshift.tf
    "CKV_AWS_87",
    "CKV_AWS_64",
    "CKV_AWS_71",
    "CKV_AWS_321",
    "CKV_AWS_142",
    "CKV_AWS_154",
    "CKV_AWS_391",
    # waf.tf
    "CKV_AWS_192",
    "CKV_AWS_175",
    "CKV2_AWS_31",
}


def test_registry_expansion_ids_are_mapped(registry):
    """Every check confirmed firing on the end2end fixtures is mapped, so none
    of them can silently degrade to an unmapped finding."""
    absent = sorted(cid for cid in EXPANSION_IDS if cid not in registry)
    assert not absent, f"expansion IDs missing from the registry: {absent}"


@pytest.mark.parametrize("cid", sorted(EXPANSION_IDS))
def test_registry_expansion_entry_is_complete(registry, cid):
    """Each expansion entry carries articles, risk, remediation and a severity
    — an entry with an empty field enriches to a blank report row."""
    m = registry[cid]
    assert m.articles, f"{cid} has no articles"
    assert m.risk_explanation.strip(), f"{cid} has no risk text"
    assert m.remediation.strip(), f"{cid} has no remediation text"
    assert isinstance(m.severity, Severity), f"{cid} has no severity"


@pytest.mark.parametrize("cid", ["CKV_AWS_87", "CKV_AWS_64"])
def test_redshift_severity_matches_rds_precedent(registry, cid):
    """Redshift exposure/encryption were calibrated against the RDS entries:
    a public data warehouse is CRITICAL (matches CKV_AWS_17) and an unencrypted
    one is HIGH (matches CKV_AWS_16)."""
    assert cid in registry, f"{cid} not in registry"
    assert (
        registry[cid].severity
        == registry["CKV_AWS_17" if cid == "CKV_AWS_87" else "CKV_AWS_16"].severity
    )


def test_nis2_only_expansion_entries_have_no_gdpr_article(registry):
    """CKV_AWS_321 (enhanced VPC routing) is a network-path control, not a
    confidentiality measure — it is NIS2-only by design (methodology note 3 in
    docs/check-mapping-table.md)."""
    if "CKV_AWS_321" not in registry:
        pytest.skip("CKV_AWS_321 not in registry")
    assert _gdpr(registry["CKV_AWS_321"]) == set()
    assert "Art. 21(2)(i)" in _nis2(registry["CKV_AWS_321"])
