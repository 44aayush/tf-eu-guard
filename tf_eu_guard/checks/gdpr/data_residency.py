"""
Custom Checkov checks for AWS region policy and transfer review.

The project has two deliberately separate signals:

* ``EUGUARD_GDPR_001`` is the project's EUSC-only sovereignty policy. It flags
  commercial EU regions such as ``eu-central-1`` because they are outside the
  chosen AWS partition, without making a GDPR Chapter V claim.
* ``EUGUARD_GDPR_002`` is a narrower Chapter V review signal. It fires only
  for a known AWS region outside the EU/EEA, such as ``us-east-1``. It does
  not decide whether a transfer is lawful; adequacy decisions, SCCs, BCRs or
  another Chapter V mechanism still require human review.

Design note: region is configured on the AWS *provider*, not on individual
resources (``aws_s3_bucket`` / ``aws_db_instance`` / ``aws_instance`` have no
``region`` argument), so this is a provider-level check. Each ``provider "aws"``
block's ``region`` is inspected; resources deployed via an out-of-policy aliased
provider (e.g. ``provider = aws.non_eusc``) inherit the finding flagged on that
block.

This deliberately deviates from the resource-level sketch in PROJECT_PLAN.md
§3.1, which would return UNKNOWN for every resource because the ``region``
attribute never appears in a resource's configuration.

For the sovereignty policy, region classification is fail-closed: the explicit
allowlist — :data:`tf_eu_guard.regions.EUSC_REGIONS`, not AWS's "eu-" naming
prefix — is the source of truth. The prefix is a *geographic*
("Europe") label, not an EU-membership one, and no longer a residency signal
at all under this policy: ``eu-west-2`` (London, UK) and ``eu-central-2``
(Zurich, Switzerland) are GDPR third countries, and the commercial EU regions
(``eu-central-1`` et al.) are GDPR-permissible but outside the Sovereign Cloud.
Any region not on the allowlist — non-EUSC regions, malformed strings, and
unresolved variable references (``var.region`` / ``"${var.region}"``, which
Checkov passes through as raw text) — fails the policy check: a deployment
target that cannot be proven to be the Sovereign Cloud statically is flagged
for review, not waved through. The Chapter V check uses a separate known-region
table and leaves unknown values undecided.
"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.provider.base_check import BaseProviderCheck

from tf_eu_guard.regions import EU_EEA_REGIONS, EUSC_REGIONS, KNOWN_AWS_REGIONS


class EURegionEnforcement(BaseProviderCheck):
    """Flag AWS provider blocks outside the project's EUSC-only policy."""

    def __init__(self):
        name = (
            "Ensure the AWS provider region is in the EU Sovereign Cloud "
            "(project sovereignty policy)"
        )
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
        """Return PASSED only for an allowlisted EUSC region; else FAILED.

        UNKNOWN is reserved for the genuinely undecidable no-information
        cases: the region is unset on this provider block (inherited at apply
        time from the environment or instance metadata) or is blank/non-string.
        Everything else fails closed — a literal out-of-policy region (non-EU
        *or* commercial EU), an unrecognized or malformed region string, and
        an unresolved variable reference all produce a finding, because a
        deployment target that cannot be proven to be the Sovereign Cloud
        statically must be reviewed rather than waved through.
        """
        region = _first_scalar(conf.get("region"))

        # Region not set on this provider block → inherited at apply time.
        if region is None:
            return CheckResult.UNKNOWN

        # Blank / non-string → no usable signal either way.
        if not isinstance(region, str) or not region.strip():
            return CheckResult.UNKNOWN

        if region.strip().lower() in EUSC_REGIONS:
            return CheckResult.PASSED
        return CheckResult.FAILED


class ThirdCountryTransferReview(BaseProviderCheck):
    """Flag known non-EU/EEA AWS regions for a hedged Chapter V review."""

    def __init__(self):
        name = (
            "Review AWS provider regions outside the EU/EEA for GDPR Chapter V "
            "transfer safeguards"
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
        region = _first_scalar(conf.get("region"))
        if not isinstance(region, str) or not region.strip():
            return CheckResult.UNKNOWN

        normalized = region.strip().lower()
        if normalized in EU_EEA_REGIONS:
            return CheckResult.PASSED
        if normalized in KNOWN_AWS_REGIONS and normalized not in EU_EEA_REGIONS:
            return CheckResult.FAILED
        return CheckResult.UNKNOWN


def _first_scalar(value):
    """Unwrap Checkov's single-element list wrapping around attribute values."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


check = EURegionEnforcement()
transfer_review_check = ThirdCountryTransferReview()
