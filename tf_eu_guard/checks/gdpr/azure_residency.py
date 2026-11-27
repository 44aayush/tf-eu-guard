"""
Custom Checkov checks for Azure resource locations.

Mirrors the AWS resource-level checks in :mod:`tf_eu_guard.checks.gdpr.data_residency`:

* ``EUGUARD_POLICY_003`` enforces the configured *residency policy* (see
  :mod:`tf_eu_guard.residency`) over the ``location`` of every ``azurerm_*``
  resource. It is fail-closed: a location off the allowlist -- including a
  location not yet verified, a malformed string or an unresolved variable
  reference -- fails. It is a project-policy finding, not a legal conclusion.
  EUSC is an AWS partition, so ``eusc`` uses the Azure EU/EEA table here.
* ``EUGUARD_GDPR_004`` is a narrower Chapter V review signal. It fails only for
  a known third-country location (the UK and Switzerland included) and leaves
  every other value undecided; it does not decide whether a transfer is lawful.

Locations are compared in normalised form ("West Europe" == "westeurope").
Only the top-level ``location`` argument is evaluated.
"""

import os

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

from tf_eu_guard.checks.values import unwrap_checkov_scalar
from tf_eu_guard.regions import (
    AZURE_EU_EEA_LOCATIONS,
    AZURE_KNOWN_LOCATIONS,
    normalise_azure_location,
)
from tf_eu_guard.residency import allowed_regions_from_env


def _location(conf):
    """Return the normalised ``location``, or None when there is no usable value."""
    value = unwrap_checkov_scalar(conf.get("location"))
    if not isinstance(value, str) or not value.strip():
        return None
    return normalise_azure_location(value)


class AzureLocationPolicy(BaseResourceCheck):
    """Flag Azure resource locations outside the configured residency policy."""

    def __init__(self):
        super().__init__(
            name="Ensure Azure resource locations are within the configured residency policy",
            id="EUGUARD_POLICY_003",
            categories=[CheckCategories.GENERAL_SECURITY],
            supported_resources=["azurerm_*"],
        )

    def scan_resource_conf(self, conf):
        """PASSED for an allowlisted location, FAILED otherwise; no location is UNKNOWN."""
        location = _location(conf)
        if location is None:
            return CheckResult.UNKNOWN
        self.evaluated_keys = ["location"]
        allowed = {
            normalise_azure_location(item) for item in allowed_regions_from_env(os.environ, "azure")
        }
        return CheckResult.PASSED if location in allowed else CheckResult.FAILED


class AzureLocationTransferReview(BaseResourceCheck):
    """Flag known non-EU/EEA Azure locations for a hedged Chapter V review."""

    def __init__(self):
        super().__init__(
            name=(
                "Review Azure resource locations outside the EU/EEA for GDPR Chapter V "
                "transfer safeguards"
            ),
            id="EUGUARD_GDPR_004",
            categories=[CheckCategories.GENERAL_SECURITY],
            supported_resources=["azurerm_*"],
        )

    def scan_resource_conf(self, conf):
        """FAILED only for a known third-country location; EU/EEA PASSED; else UNKNOWN."""
        location = _location(conf)
        if location is None:
            return CheckResult.UNKNOWN
        self.evaluated_keys = ["location"]
        if location in AZURE_EU_EEA_LOCATIONS:
            return CheckResult.PASSED
        if location in AZURE_KNOWN_LOCATIONS:
            return CheckResult.FAILED
        return CheckResult.UNKNOWN


policy_check = AzureLocationPolicy()
transfer_review_check = AzureLocationTransferReview()
