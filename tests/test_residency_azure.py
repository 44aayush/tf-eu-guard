"""Azure residency policy and Chapter V review checks (TEG-05)."""

import json

import pytest
from checkov.common.models.enums import CheckResult

from tests.cli_helpers import run_cli
from tf_eu_guard.checks.gdpr.azure_residency import (
    AzureLocationPolicy,
    AzureLocationTransferReview,
)
from tf_eu_guard.regions import (
    AZURE_EU_EEA_LOCATIONS,
    AZURE_KNOWN_LOCATIONS,
    EU_EEA_REGIONS,
    EUSC_REGIONS,
    normalise_azure_location,
)
from tf_eu_guard.residency import (
    ALLOWED_REGIONS_ENV_VAR,
    POLICY_ENV_VAR,
    allowed_regions_from_env,
)

FIXTURE = "tests/fixtures/residency-azure"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv(POLICY_ENV_VAR, raising=False)
    monkeypatch.delenv(ALLOWED_REGIONS_ENV_VAR, raising=False)


def _scan(location):
    conf = {} if location is None else {"location": [location]}
    policy = AzureLocationPolicy()
    policy.entity_type = "azurerm_resource_group"
    review = AzureLocationTransferReview()
    review.entity_type = "azurerm_resource_group"
    return policy.scan_resource_conf(conf), review.scan_resource_conf(conf)


def test_azure_location_normalisation():
    assert normalise_azure_location("West Europe") == "westeurope"
    assert normalise_azure_location("north-europe") == "northeurope"
    assert normalise_azure_location(" Germany_West_Central ") == "germanywestcentral"
    assert _scan("West Europe") == (CheckResult.PASSED, CheckResult.PASSED)


def test_azure_eu_location_passes():
    for location in ("westeurope", "francecentral", "swedencentral"):
        assert _scan(location) == (CheckResult.PASSED, CheckResult.PASSED)
    assert AZURE_EU_EEA_LOCATIONS <= AZURE_KNOWN_LOCATIONS


def test_azure_us_location_fails_both():
    assert _scan("eastus") == (CheckResult.FAILED, CheckResult.FAILED)


def test_azure_uk_location_fails_both():
    assert _scan("uksouth") == (CheckResult.FAILED, CheckResult.FAILED)


def test_azure_unverified_eu_location_fails_policy_only():
    assert "belgiumcentral" not in AZURE_KNOWN_LOCATIONS
    assert _scan("belgiumcentral") == (CheckResult.FAILED, CheckResult.UNKNOWN)


def test_azure_unresolved_var_fails_policy_unknown_transfer():
    assert _scan("var.location") == (CheckResult.FAILED, CheckResult.UNKNOWN)
    assert _scan(None) == (CheckResult.UNKNOWN, CheckResult.UNKNOWN)


def test_azure_custom_policy(monkeypatch):
    monkeypatch.setenv(POLICY_ENV_VAR, "custom")
    monkeypatch.setenv(ALLOWED_REGIONS_ENV_VAR, "westeurope,north-europe")
    assert _scan("West Europe")[0] == CheckResult.PASSED
    assert _scan("northeurope")[0] == CheckResult.PASSED
    assert _scan("francecentral")[0] == CheckResult.FAILED


def test_allowed_regions_per_cloud():
    assert allowed_regions_from_env({}) == EU_EEA_REGIONS
    assert allowed_regions_from_env({}, "azure") == AZURE_EU_EEA_LOCATIONS
    eusc = {POLICY_ENV_VAR: "eusc"}
    assert allowed_regions_from_env(eusc) == EUSC_REGIONS
    assert allowed_regions_from_env(eusc, "azure") == AZURE_EU_EEA_LOCATIONS
    custom = {POLICY_ENV_VAR: "custom", ALLOWED_REGIONS_ENV_VAR: "westeurope"}
    assert allowed_regions_from_env(custom, "azure") == frozenset({"westeurope"})
    for bad in ({POLICY_ENV_VAR: "custom"}, {POLICY_ENV_VAR: "bogus"}):
        assert allowed_regions_from_env(bad) == EUSC_REGIONS
        assert allowed_regions_from_env(bad, "azure") == frozenset()


def test_unusable_custom_allowlist_fails_azure_closed(monkeypatch):
    monkeypatch.setenv(POLICY_ENV_VAR, "custom")
    assert _scan("westeurope")[0] == CheckResult.FAILED


def test_unsupported_cloud_is_rejected():
    with pytest.raises(ValueError):
        allowed_regions_from_env({}, "oracle")


def test_check_identities():
    assert AzureLocationPolicy().id == "EUGUARD_POLICY_003"
    assert AzureLocationTransferReview().id == "EUGUARD_GDPR_004"


def test_azure_end_to_end_live(monkeypatch, tmp_path, repo_root, capsys):
    run_cli(monkeypatch, tmp_path, str(repo_root / FIXTURE), "--output", "json")
    findings = json.loads(capsys.readouterr().out)
    ids = {f["check_id"] for f in findings if f["resource"] == "azurerm_resource_group.us"}
    assert {"EUGUARD_POLICY_003", "EUGUARD_GDPR_004"} <= ids
