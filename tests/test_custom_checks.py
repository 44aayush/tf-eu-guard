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
