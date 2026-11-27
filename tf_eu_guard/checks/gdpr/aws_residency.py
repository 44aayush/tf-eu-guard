"""
Custom Checkov checks for AWS region policy and transfer review.

Three signals, deliberately separate:

* ``EUGUARD_POLICY_001`` (provider block) and ``EUGUARD_POLICY_002`` (resource
  level) enforce the configured *residency policy*: ``eu-eea`` (default; the
  EU/EEA commercial regions plus the AWS European Sovereign Cloud), ``eusc``
  (Sovereign Cloud only) or ``custom`` (``--allowed-regions``). They are
  project-policy findings, not GDPR legal conclusions. The policy reaches the
  checks, which run inside the Checkov subprocess, through the
  ``TF_EU_GUARD_RESIDENCY_POLICY`` / ``TF_EU_GUARD_ALLOWED_REGIONS``
  environment variables (see :mod:`tf_eu_guard.residency`), read at scan time.
* ``EUGUARD_GDPR_002`` (provider block) and ``EUGUARD_GDPR_003`` (resource
  level) are narrower Chapter V review signals. They fire only for a known AWS
  region outside the EU/EEA, such as ``us-east-1``. They do not decide whether
  a transfer is lawful; adequacy decisions, SCCs, BCRs or another Chapter V
  mechanism still require human review.

Where regions are set: the AWS provider block's ``region`` is the default
deployment target, so the provider checks inspect each ``provider "aws"``
block (resources using an out-of-policy aliased provider inherit the finding
on that block). Since AWS provider 6.0 most resources also accept a top-level
``region`` argument that overrides the provider, and some resources place data
in other regions through replica settings (DynamoDB global-table replicas,
Secrets Manager replicas, ECR replication destinations, Backup copy-action
vaults). The resource-level checks cover those shapes; see
:mod:`tf_eu_guard.checks.regions_conf`. S3 replication destinations are bucket
ARNs whose region is not resolvable statically and are not covered.

Policy classification is fail-closed: the explicit allowlist, not AWS's "eu-"
naming prefix, is the source of truth (``eu-west-2`` London and
``eu-central-2`` Zurich are GDPR third countries). Any region off the allowlist
-- including malformed strings and unresolved variable references
(``var.region`` / ``"${var.region}"``, which Checkov passes through as raw
text) -- fails the policy checks. The Chapter V checks use a separate
known-region table and leave unknown values undecided.
"""

import os

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.provider.base_check import BaseProviderCheck
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

from tf_eu_guard.checks.regions_conf import collect_regions
from tf_eu_guard.checks.values import unwrap_checkov_scalar
from tf_eu_guard.regions import EU_EEA_REGIONS, KNOWN_AWS_REGIONS
from tf_eu_guard.residency import allowed_regions_from_env


class EURegionEnforcement(BaseProviderCheck):
    """Flag AWS provider blocks outside the configured residency policy."""

    def __init__(self):
        name = "Ensure the AWS provider region is within the configured residency policy"
        check_id = "EUGUARD_POLICY_001"
        supported_provider = ["aws"]
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(
            name=name,
            id=check_id,
            categories=categories,
            supported_provider=supported_provider,
        )

    def scan_provider_conf(self, conf):
        """Return PASSED only for a region in the active policy; else FAILED.

        UNKNOWN is reserved for the genuinely undecidable no-information
        cases: the region is unset on this provider block (inherited at apply
        time from the environment or instance metadata) or is blank/non-string.
        Everything else fails closed — a literal out-of-policy region, an unrecognized or malformed region string, and
        an unresolved variable reference all produce a finding, because a
        deployment target that cannot be proven to be in policy
        statically must be reviewed rather than waved through.
        """
        region = unwrap_checkov_scalar(conf.get("region"))

        # Region not set on this provider block → inherited at apply time.
        if region is None:
            return CheckResult.UNKNOWN

        # Blank / non-string → no usable signal either way.
        if not isinstance(region, str) or not region.strip():
            return CheckResult.UNKNOWN

        if region.strip().lower() in allowed_regions_from_env(os.environ):
            return CheckResult.PASSED
        return CheckResult.FAILED


class ThirdCountryTransferReview(BaseProviderCheck):
    """Flag known non-EU/EEA AWS regions for a hedged Chapter V review."""

    def __init__(self):
        name = (
            "Review AWS provider regions outside the EU/EEA for GDPR Chapter V transfer safeguards"
        )
        check_id = "EUGUARD_GDPR_002"
        supported_provider = ["aws"]
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(
            name=name,
            id=check_id,
            categories=categories,
            supported_provider=supported_provider,
        )

    def scan_provider_conf(self, conf):
        """Return FAILED only for a known third-country region.

        Commercial EU/EEA and EUSC regions are not Chapter V signals. An unset,
        unresolved, malformed, or otherwise unknown region is left UNKNOWN:
        this check must not turn a lack of static information into a legal
        conclusion.
        """
        region = unwrap_checkov_scalar(conf.get("region"))
        if not isinstance(region, str) or not region.strip():
            return CheckResult.UNKNOWN

        normalized = region.strip().lower()
        if normalized in EU_EEA_REGIONS:
            return CheckResult.PASSED
        if normalized in KNOWN_AWS_REGIONS and normalized not in EU_EEA_REGIONS:
            return CheckResult.FAILED
        return CheckResult.UNKNOWN


check = EURegionEnforcement()
transfer_review_check = ThirdCountryTransferReview()


class ResourceRegionPolicy(BaseResourceCheck):
    """Flag resource-level regions outside the configured residency policy."""

    def __init__(self):
        name = (
            "Ensure resource regions (region argument, replicas, copy destinations) "
            "are within the configured residency policy"
        )
        super().__init__(
            name=name,
            id="EUGUARD_POLICY_002",
            categories=[CheckCategories.GENERAL_SECURITY],
            supported_resources=["aws_*"],
        )

    def scan_resource_conf(self, conf):
        """PASSED if every collected region is in policy; FAILED on any other.

        No region information at all is UNKNOWN. A literal region outside the
        policy, or an unresolved variable in an explicit region attribute,
        fails closed. ``evaluated_keys`` lists the offending attributes.
        """
        refs = collect_regions(self.entity_type, conf)
        if not refs:
            return CheckResult.UNKNOWN
        allowed = allowed_regions_from_env(os.environ)
        offending = [ref.key for ref in refs if ref.region not in allowed]
        if offending:
            self.evaluated_keys = offending
            return CheckResult.FAILED
        self.evaluated_keys = [ref.key for ref in refs]
        return CheckResult.PASSED


class ResourceThirdCountryTransferReview(BaseResourceCheck):
    """Flag resource-level known non-EU/EEA regions for Chapter V review."""

    def __init__(self):
        name = (
            "Review resource regions outside the EU/EEA (region argument, replicas, "
            "copy destinations) for GDPR Chapter V transfer safeguards"
        )
        super().__init__(
            name=name,
            id="EUGUARD_GDPR_003",
            categories=[CheckCategories.GENERAL_SECURITY],
            supported_resources=["aws_*"],
        )

    def scan_resource_conf(self, conf):
        """FAILED only if a collected region is a known third-country region.

        EU/EEA (including EUSC) is PASSED; unknown or unresolved regions are
        left UNKNOWN rather than turned into a legal conclusion.
        """
        refs = collect_regions(self.entity_type, conf)
        third_country = [
            ref.key
            for ref in refs
            if ref.region in KNOWN_AWS_REGIONS and ref.region not in EU_EEA_REGIONS
        ]
        if third_country:
            self.evaluated_keys = third_country
            return CheckResult.FAILED
        if refs and all(ref.region in EU_EEA_REGIONS for ref in refs):
            self.evaluated_keys = [ref.key for ref in refs]
            return CheckResult.PASSED
        return CheckResult.UNKNOWN


resource_policy_check = ResourceRegionPolicy()
resource_transfer_review_check = ResourceThirdCountryTransferReview()
