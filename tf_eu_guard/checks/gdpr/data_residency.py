"""
Custom Checkov check: EU data-residency enforcement (GDPR Chapter V, Art. 44-49).

Deploying AWS resources through a provider pinned to a non-EU region stores
personal data outside the EU/EEA — a transfer to a third country. GDPR Art. 44
permits such transfers only under the safeguards of Chapter V, so infrastructure
that configures a non-EU region is flagged for review.

Design note: region is configured on the AWS *provider*, not on individual
resources (``aws_s3_bucket`` / ``aws_db_instance`` / ``aws_instance`` have no
``region`` argument), so this is a provider-level check. Each ``provider "aws"``
block's ``region`` is inspected; resources deployed via a non-EU aliased provider
(e.g. ``provider = aws.non_eu``) inherit the finding flagged on that block.

This deliberately deviates from the resource-level sketch in PROJECT_PLAN.md
§3.1, which would return UNKNOWN for every resource because the ``region``
attribute never appears in a resource's configuration.
"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.provider.base_check import BaseProviderCheck

# AWS region prefixes whose regions keep data inside the EU/EEA.
# "eu-" covers eu-west-1/eu-central-1/etc.; "eusc-" is the AWS European
# Sovereign Cloud partition.
_EU_REGION_PREFIXES = ("eu-", "eusc-")


class EURegionEnforcement(BaseProviderCheck):
    """Flag AWS provider blocks configured for a non-EU region."""

    def __init__(self):
        name = "Ensure the AWS provider region is in the EU (GDPR data residency, Art. 44-49)"
        check_id = "EUGUARD_GDPR_001"
        supported_provider = ["aws"]
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(
            name=name,
            id=check_id,
            categories=categories,
            supported_provider=supported_provider,
        )

    def scan_provider_conf(self, conf):
        """Return FAILED for a literal non-EU region, PASSED for an EU region.

        UNKNOWN is returned when no decision can be made — the region is unset
        (inherited from the environment/instance metadata) or is still an
        unresolved variable/interpolation.
        """
        region = _first_scalar(conf.get("region"))

        # Region not set on this provider block → inherited at apply time.
        if region is None:
            return CheckResult.UNKNOWN

        # Unresolved variable / interpolation (e.g. "${var.region}").
        if not isinstance(region, str) or "${" in region or not region.strip():
            return CheckResult.UNKNOWN

        if region.strip().lower().startswith(_EU_REGION_PREFIXES):
            return CheckResult.PASSED
        return CheckResult.FAILED


def _first_scalar(value):
    """Unwrap Checkov's single-element list wrapping around attribute values."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


check = EURegionEnforcement()
