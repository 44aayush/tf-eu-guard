"""
Custom Checkov checks for GCP regions and locations.

Mirrors the AWS and Azure residency checks (:mod:`tf_eu_guard.checks.gdpr.data_residency`,
:mod:`tf_eu_guard.checks.gdpr.azure_residency`). The provider-block and resource-level
classes share one check ID each, because they enforce one rule at two levels:

* ``EUGUARD_POLICY_004`` enforces the configured *residency policy* (see
  :mod:`tf_eu_guard.residency`) over the ``region`` of each ``provider "google"``
  block (``region`` and ``zone``) and the ``region``, ``location`` and ``zone`` of every ``google_*`` resource.
  It is fail-closed: a location off the allowlist -- including a dual-region or newer
  location not yet verified, a malformed string or an unresolved variable reference --
  fails. It is a project-policy finding, not a legal conclusion. EUSC is an AWS
  partition, so ``eusc`` uses the GCP EU/EEA table here.
* ``EUGUARD_GDPR_005`` is a narrower Chapter V review signal. It fails only for a
  known third-country location (the UK and Switzerland included) and leaves every
  other value undecided; it does not decide whether a transfer is lawful.

Locations are compared in normalised form: lower case, a zone mapped to its region
(``europe-west4-a`` is ``europe-west4``), the multi-region ``EU`` equal to ``eu``.
"""

import os

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.provider.base_check import BaseProviderCheck
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

from tf_eu_guard.checks.values import unwrap_checkov_scalar
from tf_eu_guard.regions import (
    GCP_EU_EEA_LOCATIONS,
    GCP_KNOWN_LOCATIONS,
    normalise_gcp_location,
)
from tf_eu_guard.residency import allowed_regions_from_env

POLICY_ID = "EUGUARD_POLICY_004"
POLICY_NAME = "Ensure GCP regions and locations are within the configured residency policy"
REVIEW_ID = "EUGUARD_GDPR_005"
REVIEW_NAME = (
    "Review GCP regions and locations outside the EU/EEA for GDPR Chapter V transfer safeguards"
)
_RESOURCE_KEYS = ("region", "location", "zone")
_PROVIDER_KEYS = ("region", "zone")


def _locations(conf, keys):
    """Return ``{key: normalised value}`` for each usable string argument in *keys*."""
    found = {}
    for key in keys:
        value = unwrap_checkov_scalar(conf.get(key))
        if isinstance(value, str) and value.strip():
            found[key] = normalise_gcp_location(value)
    return found


def _policy_result(found):
    """PASSED if every location is allowlisted, FAILED otherwise, UNKNOWN if none."""
    if not found:
        return CheckResult.UNKNOWN, []
    allowed = {normalise_gcp_location(item) for item in allowed_regions_from_env(os.environ, "gcp")}
    offending = [key for key, location in found.items() if location not in allowed]
    if offending:
        return CheckResult.FAILED, offending
    return CheckResult.PASSED, list(found)


def _review_result(found):
    """FAILED for a known third country, PASSED if all are EU/EEA, else UNKNOWN."""
    third_country = [
        key
        for key, location in found.items()
        if location in GCP_KNOWN_LOCATIONS and location not in GCP_EU_EEA_LOCATIONS
    ]
    if third_country:
        return CheckResult.FAILED, third_country
    if found and all(location in GCP_EU_EEA_LOCATIONS for location in found.values()):
        return CheckResult.PASSED, list(found)
    return CheckResult.UNKNOWN, []


class GcpProviderRegionPolicy(BaseProviderCheck):
    """Flag ``provider "google"`` regions and zones outside the configured residency policy."""

    def __init__(self):
        super().__init__(
            name=POLICY_NAME,
            id=POLICY_ID,
            categories=[CheckCategories.GENERAL_SECURITY],
            supported_provider=["google", "google-beta"],
        )

    def scan_provider_conf(self, conf):
        """PASSED for an allowlisted region or zone, FAILED otherwise; none set is UNKNOWN."""
        result, keys = _policy_result(_locations(conf, _PROVIDER_KEYS))
        self.evaluated_keys = keys
        return result


class GcpProviderRegionTransferReview(BaseProviderCheck):
    """Flag known non-EU/EEA GCP provider regions for a hedged Chapter V review."""

    def __init__(self):
        super().__init__(
            name=REVIEW_NAME,
            id=REVIEW_ID,
            categories=[CheckCategories.GENERAL_SECURITY],
            supported_provider=["google", "google-beta"],
        )

    def scan_provider_conf(self, conf):
        """FAILED only for a known third-country region; EU/EEA PASSED; else UNKNOWN."""
        result, keys = _review_result(_locations(conf, _PROVIDER_KEYS))
        self.evaluated_keys = keys
        return result


class GcpLocationPolicy(BaseResourceCheck):
    """Flag GCP resource locations outside the configured residency policy."""

    def __init__(self):
        super().__init__(
            name=POLICY_NAME,
            id=POLICY_ID,
            categories=[CheckCategories.GENERAL_SECURITY],
            supported_resources=["google_*"],
        )

    def scan_resource_conf(self, conf):
        """PASSED if every region/location/zone is allowlisted; FAILED on any other."""
        result, keys = _policy_result(_locations(conf, _RESOURCE_KEYS))
        self.evaluated_keys = keys
        return result


class GcpLocationTransferReview(BaseResourceCheck):
    """Flag known non-EU/EEA GCP resource locations for a hedged Chapter V review."""

    def __init__(self):
        super().__init__(
            name=REVIEW_NAME,
            id=REVIEW_ID,
            categories=[CheckCategories.GENERAL_SECURITY],
            supported_resources=["google_*"],
        )

    def scan_resource_conf(self, conf):
        """FAILED only for a known third-country location; EU/EEA PASSED; else UNKNOWN."""
        result, keys = _review_result(_locations(conf, _RESOURCE_KEYS))
        self.evaluated_keys = keys
        return result


provider_policy_check = GcpProviderRegionPolicy()
provider_transfer_review_check = GcpProviderRegionTransferReview()
policy_check = GcpLocationPolicy()
transfer_review_check = GcpLocationTransferReview()
