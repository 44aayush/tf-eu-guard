"""
Custom Checkov check: EU data-residency enforcement (GDPR Chapter V, Art. 44-49).

This project is based on the AWS European Sovereign Cloud: only EUSC regions
are acceptable deployment targets. Any other region — a non-EU region (which
under GDPR Art. 44 is a transfer to a third country requiring Chapter V
safeguards) or a *commercial* EU region such as ``eu-central-1`` (which GDPR
would permit, but which does not meet this project's sovereignty requirement) —
is flagged for review.

Design note: region is configured on the AWS *provider*, not on individual
resources (``aws_s3_bucket`` / ``aws_db_instance`` / ``aws_instance`` have no
``region`` argument), so this is a provider-level check. Each ``provider "aws"``
block's ``region`` is inspected; resources deployed via an out-of-policy aliased
provider (e.g. ``provider = aws.non_eusc``) inherit the finding flagged on that
block.

This deliberately deviates from the resource-level sketch in PROJECT_PLAN.md
§3.1, which would return UNKNOWN for every resource because the ``region``
attribute never appears in a resource's configuration.

Region classification is fail-closed: the explicit allowlist —
:data:`tf_eu_guard.regions.EUSC_REGIONS`, not AWS's "eu-" naming prefix —
is the source of truth. The prefix is a *geographic*
("Europe") label, not an EU-membership one, and no longer a residency signal
at all under this policy: ``eu-west-2`` (London, UK) and ``eu-central-2``
(Zurich, Switzerland) are GDPR third countries, and the commercial EU regions
(``eu-central-1`` et al.) are GDPR-permissible but outside the Sovereign Cloud.
Any region not on the allowlist — non-EUSC regions, malformed strings, and
unresolved variable references (``var.region`` / ``"${var.region}"``, which
Checkov passes through as raw text) — fails the check: a deployment target
that cannot be proven to be the Sovereign Cloud statically is flagged for
review, not waved through.
"""

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.provider.base_check import BaseProviderCheck

from tf_eu_guard.regions import EUSC_REGIONS


class EURegionEnforcement(BaseProviderCheck):
    """Flag AWS provider blocks configured outside the EU Sovereign Cloud."""

    def __init__(self):
        name = (
            "Ensure the AWS provider region is in the EU Sovereign Cloud "
            "(GDPR data residency, Art. 44-49)"
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


def _first_scalar(value):
    """Unwrap Checkov's single-element list wrapping around attribute values."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


check = EURegionEnforcement()
