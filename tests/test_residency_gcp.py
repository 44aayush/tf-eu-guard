"""GCP residency policy and Chapter V review checks (TEG-05)."""

import json

import pytest
from checkov.common.models.enums import CheckResult

from tests.cli_helpers import run_cli
from tf_eu_guard.checks.gdpr.gcp_residency import (
    GcpLocationPolicy,
    GcpLocationTransferReview,
    GcpProviderRegionPolicy,
    GcpProviderRegionTransferReview,
)
from tf_eu_guard.regions import (
    GCP_EU_EEA_LOCATIONS,
    GCP_KNOWN_LOCATIONS,
    normalise_gcp_location,
)
from tf_eu_guard.residency import (
    ALLOWED_REGIONS_ENV_VAR,
    POLICY_ENV_VAR,
    allowed_regions_from_env,
)

FIXTURE = "tests/fixtures/residency-gcp"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv(POLICY_ENV_VAR, raising=False)
    monkeypatch.delenv(ALLOWED_REGIONS_ENV_VAR, raising=False)


def _scan(conf):
    """Run the resource policy and review checks over a resource conf."""
    policy = GcpLocationPolicy()
    policy.entity_type = "google_storage_bucket"
    review = GcpLocationTransferReview()
    review.entity_type = "google_storage_bucket"
    return policy.scan_resource_conf(conf), review.scan_resource_conf(conf)


def _loc(location):
    return _scan({} if location is None else {"location": [location]})


def test_gcp_location_normalisation():
    assert normalise_gcp_location("EU") == "eu"
    assert normalise_gcp_location(" US ") == "us"
    assert normalise_gcp_location("ASIA") == "asia"
    assert normalise_gcp_location("Europe-West4") == "europe-west4"
    assert normalise_gcp_location("europe-west4-a") == "europe-west4"
    assert _loc("EU") == (CheckResult.PASSED, CheckResult.PASSED)


def test_gcp_eu_region_and_multiregion_pass():
    for location in ("europe-west1", "europe-north2", "europe-southwest1", "eu", "EU"):
        assert _loc(location) == (CheckResult.PASSED, CheckResult.PASSED)
    assert GCP_EU_EEA_LOCATIONS <= GCP_KNOWN_LOCATIONS


def test_gcp_london_and_zurich_fail_both():
    for location in ("europe-west2", "europe-west6"):
        assert _loc(location) == (CheckResult.FAILED, CheckResult.FAILED)


def test_gcp_us_multiregion_fails_both():
    assert _loc("US") == (CheckResult.FAILED, CheckResult.FAILED)
    assert _loc("us-central1") == (CheckResult.FAILED, CheckResult.FAILED)


def test_gcp_unverified_location_fails_policy_only():
    assert "eur4" not in GCP_KNOWN_LOCATIONS
    assert _loc("EUR4") == (CheckResult.FAILED, CheckResult.UNKNOWN)
    assert _loc("var.location") == (CheckResult.FAILED, CheckResult.UNKNOWN)
    assert _loc(None) == (CheckResult.UNKNOWN, CheckResult.UNKNOWN)


def test_gcp_zone_maps_to_region():
    assert _scan({"zone": ["europe-west4-a"]}) == (CheckResult.PASSED, CheckResult.PASSED)
    assert _scan({"zone": ["us-central1-a"]}) == (CheckResult.FAILED, CheckResult.FAILED)
    assert _scan({"region": ["us-east1"]}) == (CheckResult.FAILED, CheckResult.FAILED)


def test_gcp_resource_with_several_arguments():
    conf = {"region": ["europe-west1"], "zone": ["us-central1-a"]}
    assert _scan(conf) == (CheckResult.FAILED, CheckResult.FAILED)


def test_gcp_provider_region_checked():
    policy = GcpProviderRegionPolicy()
    review = GcpProviderRegionTransferReview()
    assert (policy.scan_provider_conf({"region": ["us-central1"]})) == CheckResult.FAILED
    assert review.scan_provider_conf({"region": ["us-central1"]}) == CheckResult.FAILED
    assert policy.scan_provider_conf({"region": ["europe-west3"]}) == CheckResult.PASSED
    assert review.scan_provider_conf({"region": ["europe-west3"]}) == CheckResult.PASSED
    assert policy.scan_provider_conf({}) == CheckResult.UNKNOWN
    assert review.scan_provider_conf({"region": ["var.region"]}) == CheckResult.UNKNOWN
    assert policy.scan_provider_conf({"region": ["var.region"]}) == CheckResult.FAILED


def test_gcp_custom_policy(monkeypatch):
    monkeypatch.setenv(POLICY_ENV_VAR, "custom")
    monkeypatch.setenv(ALLOWED_REGIONS_ENV_VAR, "europe-west4,EU")
    assert _loc("europe-west4")[0] == CheckResult.PASSED
    assert _scan({"zone": ["europe-west4-b"]})[0] == CheckResult.PASSED
    assert _loc("europe-west1")[0] == CheckResult.FAILED


def test_unusable_custom_allowlist_fails_gcp_closed(monkeypatch):
    monkeypatch.setenv(POLICY_ENV_VAR, "custom")
    assert _loc("europe-west4")[0] == CheckResult.FAILED


def test_allowed_regions_gcp():
    assert allowed_regions_from_env({}, "gcp") == GCP_EU_EEA_LOCATIONS
    assert allowed_regions_from_env({POLICY_ENV_VAR: "eusc"}, "gcp") == GCP_EU_EEA_LOCATIONS
    custom = {POLICY_ENV_VAR: "custom", ALLOWED_REGIONS_ENV_VAR: "europe-west4"}
    assert allowed_regions_from_env(custom, "gcp") == frozenset({"europe-west4"})
    for bad in ({POLICY_ENV_VAR: "custom"}, {POLICY_ENV_VAR: "bogus"}):
        assert allowed_regions_from_env(bad, "gcp") == frozenset()


def test_check_identities():
    assert GcpProviderRegionPolicy().id == GcpLocationPolicy().id == "EUGUARD_POLICY_004"
    assert (
        GcpProviderRegionTransferReview().id == GcpLocationTransferReview().id == "EUGUARD_GDPR_005"
    )


def test_gcp_end_to_end_live(monkeypatch, tmp_path, repo_root, capsys):
    run_cli(monkeypatch, tmp_path, str(repo_root / FIXTURE), "--output", "json")
    findings = json.loads(capsys.readouterr().out)
    by_resource = {}
    for f in findings:
        by_resource.setdefault(f["resource"], set()).add(f["check_id"])
    assert {"EUGUARD_POLICY_004", "EUGUARD_GDPR_005"} <= by_resource["google_storage_bucket.us"]
    provider_ids = {i for r, ids in by_resource.items() if r.startswith("google.") for i in ids}
    assert {"EUGUARD_POLICY_004", "EUGUARD_GDPR_005"} <= provider_ids
