"""Phase 3 — unit tests for the custom EU-compliance Checkov checks.

Hermetic: the check classes are exercised directly with synthetic Checkov
``conf`` dicts (attribute values wrapped in single-element lists, as Checkov
produces them). No Terraform parsing or Checkov CLI run is required.

Checkov must be importable (it is a hard dependency); if it is somehow absent
the whole module skips rather than erroring at collection.
"""

import importlib.util
import os
import shutil

import pytest

pytest.importorskip("checkov")

from checkov.common.models.enums import CheckResult  # noqa: E402

from tf_eu_guard.checks.gdpr.data_residency import EURegionEnforcement  # noqa: E402
from tf_eu_guard.checks.nis2.secrets_in_code import HardcodedSecrets  # noqa: E402

# --- EUGUARD_GDPR_001: EU Sovereign Cloud region enforcement (provider check) --

# Every "eu"-prefixed region in AWS's commercial partition (verified against
# the AWS "Regions and Zones" reference and botocore's partition data,
# 2026-09). Under this project's EUSC-only policy ALL of them fail: the six
# EU/EEA ones are GDPR-permissible but not part of the Sovereign Cloud, and
# London/Zurich are GDPR third countries on top of that. When AWS launches
# a new eu- region, add it here to force the classification decision.
_COMMERCIAL_EU_PREFIXED_REGIONS = {
    "eu-central-1", "eu-central-2", "eu-north-1", "eu-south-1",
    "eu-south-2", "eu-west-1", "eu-west-2", "eu-west-3",
}

# The only acceptable deployment targets: regions of the AWS European
# Sovereign Cloud (EUSC partition in botocore's endpoint data).
_EUSC_REGIONS = {"eusc-de-east-1"}


@pytest.mark.parametrize(
    "region, expected",
    [
        # EU Sovereign Cloud regions — the allowlist
        ("eusc-de-east-1", CheckResult.PASSED),   # Brandenburg, Germany
        ("EUSC-DE-EAST-1", CheckResult.PASSED),   # case-insensitive
        ("  eusc-de-east-1  ", CheckResult.PASSED),  # surrounding whitespace
        # Commercial EU regions: GDPR-permissible, but outside the Sovereign
        # Cloud — this project's policy fails them.
        ("eu-central-1", CheckResult.FAILED),     # Frankfurt
        ("eu-west-1", CheckResult.FAILED),        # Ireland
        ("eu-west-3", CheckResult.FAILED),        # Paris
        ("eu-north-1", CheckResult.FAILED),       # Stockholm
        ("eu-south-1", CheckResult.FAILED),       # Milan
        ("eu-south-2", CheckResult.FAILED),       # Spain
        ("EU-WEST-1", CheckResult.FAILED),        # case-insensitive failure too
        # "eu-" is a geographic label, not EU membership
        ("eu-west-2", CheckResult.FAILED),        # London, UK (Brexit)
        ("eu-central-2", CheckResult.FAILED),     # Zurich, Switzerland
        # Non-EU regions
        ("us-east-1", CheckResult.FAILED),
        ("ap-southeast-2", CheckResult.FAILED),
        ("me-south-1", CheckResult.FAILED),
        # Air-gapped partition sharing the eu- prefix — not commercial AWS
        ("eu-isoe-west-1", CheckResult.FAILED),
        # Invalid / non-existent region strings fail closed
        ("eu-garbage-9", CheckResult.FAILED),
        ("eusc-de-1", CheckResult.FAILED),        # wrong EUSC code — pinned exactly
        # Unresolved variable references fail closed: a deployment target
        # that can't be proven statically is flagged, not waved through.
        # Checkov renders a bare reference as raw text ("var.region") —
        # no ${} wrapper.
        ("var.region", CheckResult.FAILED),
        ("${var.region}", CheckResult.FAILED),
        ("local.region", CheckResult.FAILED),
    ],
)
def test_region_literal_pass_fail(region, expected):
    result = EURegionEnforcement().scan_provider_conf({"region": [region]})
    assert result == expected


@pytest.mark.parametrize(
    "conf",
    [
        {},                              # no region → inherited at apply time
        {"region": []},                  # empty
        {"region": ["   "]},             # blank
        {"region": [None]},              # non-string
    ],
)
def test_region_undecidable_is_unknown(conf):
    assert EURegionEnforcement().scan_provider_conf(conf) == CheckResult.UNKNOWN


def test_every_commercial_eu_prefixed_region_is_classified():
    """Every eu-prefixed commercial region fails under the EUSC-only policy —
    including the six GDPR-permissible EU/EEA ones, and the two third
    countries (eu-west-2 London / eu-central-2 Zurich) that the old prefix
    matching waved through as "EU-compliant." """
    check = EURegionEnforcement()
    results = {
        r: check.scan_provider_conf({"region": [r]})
        for r in _COMMERCIAL_EU_PREFIXED_REGIONS
    }
    assert all(v == CheckResult.FAILED for v in results.values()), {
        r: v for r, v in results.items() if v != CheckResult.FAILED
    }


def test_region_allowlist_is_exact():
    """The allowlist — not a prefix — is the source of truth. Pin its contents
    so an accidental widening (e.g. reintroducing prefix logic or readmitting
    commercial EU regions) can't pass."""
    from tf_eu_guard.regions import EUSC_REGIONS

    assert EUSC_REGIONS == frozenset({"eusc-de-east-1"})


def test_region_check_identity():
    check = EURegionEnforcement()
    assert check.id == "EUGUARD_GDPR_001"
    assert check.supported_provider == ["aws"]


@pytest.mark.skipif(
    not os.environ.get("TFEG_RUN_CHECKOV")
    or importlib.util.find_spec("checkov") is None,
    reason="live Checkov test: set TFEG_RUN_CHECKOV=1 with Checkov installed in this Python environment",
)
def test_region_aliased_providers_live(repo_root):
    """Live regression guard for the EUSC-only allowlist, at the Checkov level.

    Exercises what the hermetic tests can't: Checkov evaluates each aliased
    ``provider "aws"`` block independently (a refactor of the matching logic
    could silently drop aliased providers), and a bare variable reference with
    no default arrives as the raw string ``var.region_no_default`` — which the
    check must fail closed rather than wave through.
    """
    from tf_eu_guard.checkov_runner import extract_failed_checks, run_checkov

    fixture = repo_root / "tests" / "fixtures" / "region-aliases"
    if not fixture.exists():
        pytest.skip("tests/fixtures/region-aliases/ not present")

    findings = extract_failed_checks(run_checkov(fixture))
    flagged = {
        c["resource"] for c in findings if c["check_id"] == "EUGUARD_GDPR_001"
    }

    # eu-prefixed third countries must produce findings on their own alias.
    assert "aws.london" in flagged
    assert "aws.zurich" in flagged
    # Commercial EU region: GDPR-permissible, but outside the Sovereign Cloud.
    assert "aws.frankfurt" in flagged
    # The Sovereign Cloud region stays passing (absent from failed_checks).
    assert "aws.sovereign" not in flagged
    # Unresolved variable with no default: fail closed, don't silently pass.
    assert "aws.bare_variable" in flagged


# --- EUGUARD_NIS2_001: hardcoded secrets (resource check) ----------------------

def _run_secret_check(entity_type: str, conf: dict) -> CheckResult:
    check = HardcodedSecrets()
    check.entity_type = entity_type  # set by Checkov's scan_entity_conf in real runs
    return check.scan_resource_conf(conf)


@pytest.mark.parametrize(
    "entity_type, field",
    [
        ("aws_db_instance", "password"),
        ("aws_rds_cluster", "master_password"),
        ("aws_redshift_cluster", "master_password"),
        ("aws_elasticache_replication_group", "auth_token"),
    ],
)
def test_literal_secret_fails(entity_type, field):
    assert _run_secret_check(entity_type, {field: ["ChangeMe123!"]}) == CheckResult.FAILED


@pytest.mark.parametrize(
    "value",
    [
        "${data.aws_secretsmanager_secret_version.db.secret_string}",
        "${var.db_password}",
        "${aws_ssm_parameter.pw.value}",
    ],
)
def test_interpolated_reference_passes(value):
    assert _run_secret_check("aws_db_instance", {"password": [value]}) == CheckResult.PASSED


@pytest.mark.parametrize(
    "conf",
    [
        {"storage_encrypted": [False]},   # no secret field present
        {"password": [""]},               # empty literal
        {"password": ["   "]},            # blank literal
    ],
)
def test_no_hardcoded_secret_passes(conf):
    assert _run_secret_check("aws_db_instance", conf) == CheckResult.PASSED


def test_unsupported_field_name_ignored():
    # A literal in an argument we don't classify as a secret must not fail.
    assert _run_secret_check("aws_db_instance", {"username": ["admin"]}) == CheckResult.PASSED


def test_secrets_check_identity():
    check = HardcodedSecrets()
    assert check.id == "EUGUARD_NIS2_001"
    assert "aws_db_instance" in check.supported_resources


# --- Cross-check: custom check IDs are mapped in the registry ------------------

def test_custom_check_ids_are_registered(registry):
    """Every custom check's id must have a registry entry, or its findings
    would be silently dropped by enrich_findings."""
    for check in (EURegionEnforcement(), HardcodedSecrets()):
        assert check.id in registry, f"{check.id} has no registry.yaml mapping"


# --- EUGUARD_NIS2_001 (Kubernetes variant) -------------------------------------

from tf_eu_guard.checks.k8s.secrets_in_code import (  # noqa: E402
    K8sContainerEnvHardcodedSecrets,
    K8sSecretManifestHardcodedSecrets,
)


def _run_k8s_secret_check(conf: dict) -> CheckResult:
    check = K8sSecretManifestHardcodedSecrets()
    check.entity_type = "Secret"
    return check.scan_spec_conf(conf)


def _run_k8s_env_check(conf: dict) -> CheckResult:
    check = K8sContainerEnvHardcodedSecrets()
    check.entity_type = "Pod"
    return check.scan_spec_conf(conf)


# Secret-manifest variant

@pytest.mark.parametrize(
    "field",
    ["stringData", "data"],
)
def test_k8s_secret_manifest_literal_fails(field):
    assert _run_k8s_secret_check({field: {"password": "ChangeMe123!"}}) == CheckResult.FAILED


@pytest.mark.parametrize(
    "conf",
    [
        {"metadata": {"name": "app-credentials"}},  # no data at all (operator-managed)
        {"data": {}, "stringData": {}},             # empty data
        {"data": {"password": ""}},                 # blank value
    ],
)
def test_k8s_secret_manifest_clean_passes(conf):
    assert _run_k8s_secret_check(conf) == CheckResult.PASSED


# Container-env variant

@pytest.mark.parametrize(
    "name",
    ["DB_PASSWORD", "API_TOKEN", "SECRET_KEY", "aws_access_key_id"],
)
def test_k8s_env_literal_sensitive_name_fails(name):
    conf = {"spec": {"containers": [{"name": "app", "env": [{"name": name, "value": "hunter2"}]}]}}
    assert _run_k8s_env_check(conf) == CheckResult.FAILED


def test_k8s_env_secret_key_ref_passes():
    conf = {"spec": {"containers": [{"name": "app", "env": [
        {"name": "DB_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "db", "key": "pw"}}}
    ]}]}}
    assert _run_k8s_env_check(conf) == CheckResult.PASSED


def test_k8s_env_nonsensitive_literal_passes():
    conf = {"spec": {"containers": [{"name": "app", "env": [
        {"name": "LOG_LEVEL", "value": "debug"}
    ]}]}}
    assert _run_k8s_env_check(conf) == CheckResult.PASSED


@pytest.mark.parametrize("name", ["DB_PASSWORD_FILE", "TLS_KEY_PATH"])
def test_k8s_env_file_pointer_convention_passes(name):
    """The _FILE / _PATH suffix points at a mounted secret file, not a literal."""
    conf = {"spec": {"containers": [{"name": "app", "env": [
        {"name": name, "value": "/etc/secrets/password"}
    ]}]}}
    assert _run_k8s_env_check(conf) == CheckResult.PASSED


def test_k8s_env_empty_value_passes():
    conf = {"spec": {"containers": [{"name": "app", "env": [{"name": "DB_PASSWORD", "value": ""}]}]}}
    assert _run_k8s_env_check(conf) == CheckResult.PASSED


def test_k8s_checks_identity():
    """Both K8s variants share the Terraform check's ID so the shared registry
    entry enriches them."""
    for check in (K8sSecretManifestHardcodedSecrets(), K8sContainerEnvHardcodedSecrets()):
        assert check.id == "EUGUARD_NIS2_001"
    assert "Secret" in K8sSecretManifestHardcodedSecrets().supported_specs
    assert "Pod" in K8sContainerEnvHardcodedSecrets().supported_specs


# --- K8s data-residency scope decision -----------------------------------------

def test_k8s_data_residency_is_scoped_out():
    """EUGUARD_GDPR_001 has no Kubernetes variant by design (DECISIONS.md #9):
    manifests are cloud-agnostic, region lives at the cluster boundary, not in
    the manifest. Guard against an accidental future import, which would
    silently do nothing."""
    import tf_eu_guard.checks.k8s as k8s_pkg

    assert not hasattr(k8s_pkg, "data_residency")
