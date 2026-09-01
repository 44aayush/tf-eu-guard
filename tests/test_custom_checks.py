"""Phase 3 — unit tests for the custom EU-compliance Checkov checks.

Hermetic: the check classes are exercised directly with synthetic Checkov
``conf`` dicts (attribute values wrapped in single-element lists, as Checkov
produces them). No Terraform parsing or Checkov CLI run is required.

Checkov must be importable (it is a hard dependency); if it is somehow absent
the whole module skips rather than erroring at collection.
"""

import pytest

pytest.importorskip("checkov")

from checkov.common.models.enums import CheckResult  # noqa: E402

from tf_eu_guard.checks.gdpr.data_residency import EURegionEnforcement  # noqa: E402
from tf_eu_guard.checks.nis2.secrets_in_code import HardcodedSecrets  # noqa: E402

# --- EUGUARD_GDPR_001: EU region enforcement (provider check) ------------------

@pytest.mark.parametrize(
    "region, expected",
    [
        ("eu-west-1", CheckResult.PASSED),
        ("eu-central-1", CheckResult.PASSED),
        ("EU-WEST-1", CheckResult.PASSED),          # case-insensitive
        ("eusc-de-east-1", CheckResult.PASSED),     # European Sovereign Cloud
        ("us-east-1", CheckResult.FAILED),
        ("ap-southeast-2", CheckResult.FAILED),
        ("me-south-1", CheckResult.FAILED),         # Middle East, not EU
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
        {"region": ["${var.region}"]},   # unresolved variable
        {"region": [None]},              # non-string
    ],
)
def test_region_undecidable_is_unknown(conf):
    assert EURegionEnforcement().scan_provider_conf(conf) == CheckResult.UNKNOWN


def test_region_check_identity():
    check = EURegionEnforcement()
    assert check.id == "EUGUARD_GDPR_001"
    assert "aws" in check.supported_provider


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
