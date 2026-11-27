"""Residency policy selection shared by the CLI and the custom Checkov checks.

The custom checks run inside a Checkov subprocess, so the CLI hands the chosen
policy over through two environment variables that only
:func:`tf_eu_guard.checkov.process.run_checkov` sets explicitly (the ambient
values are scrubbed by ``checkov_environment``). The checks read them at scan
time with :func:`allowed_regions_from_env`.

``eu-eea``  every commercial EU/EEA region plus the AWS European Sovereign Cloud
``eusc``    only the AWS European Sovereign Cloud (the 0.7.x behaviour)
``custom``  an explicit allowlist from ``--allowed-regions``

EUSC is an AWS partition: for Azure and GCP, ``eusc`` uses that cloud's EU/EEA
table, and ``custom`` applies the same allowlist to every cloud. Bad input (an
unrecognised policy, or ``custom`` without usable regions) fails closed: AWS falls back to the
EUSC-only allowlist, Azure and GCP to an empty allowlist.

Direct Checkov use (no CLI) leaves both variables unset and gets ``eu-eea``.
Bad input never silently widens the policy.
"""

import re
from collections.abc import Mapping
from typing import Any

from tf_eu_guard.regions import (
    AZURE_EU_EEA_LOCATIONS,
    EU_EEA_REGIONS,
    EUSC_REGIONS,
    GCP_EU_EEA_LOCATIONS,
)

POLICY_ENV_VAR = "TF_EU_GUARD_RESIDENCY_POLICY"
ALLOWED_REGIONS_ENV_VAR = "TF_EU_GUARD_ALLOWED_REGIONS"
RESIDENCY_ENV_VARS = (POLICY_ENV_VAR, ALLOWED_REGIONS_ENV_VAR)

POLICY_EU_EEA = "eu-eea"
POLICY_EUSC = "eusc"
POLICY_CUSTOM = "custom"
RESIDENCY_POLICIES = (POLICY_EU_EEA, POLICY_EUSC, POLICY_CUSTOM)
DEFAULT_POLICY = POLICY_EU_EEA

_REGION_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
_AWS_RESOURCE_RE = re.compile(r"(^|\.)aws_[a-z0-9_]+\.")
_GCP_RESOURCE_RE = re.compile(r"(^|\.)google_[a-z0-9_]+\.")
_CLOUDS = ("aws", "azure", "gcp")
_EU_EEA_BY_CLOUD = {"azure": AZURE_EU_EEA_LOCATIONS, "gcp": GCP_EU_EEA_LOCATIONS}
_POLICY_CHECK_ID = "EUGUARD_POLICY_001"
_GCP_POLICY_CHECK_ID = "EUGUARD_POLICY_004"


def parse_allowed_regions(text: str) -> tuple[str, ...]:
    """Normalise ``REGION[,REGION...]`` to a sorted, de-duplicated tuple.

    Raises ``ValueError`` for an empty list or a malformed region code.
    """
    regions = {part.strip().lower() for part in text.split(",") if part.strip()}
    if not regions:
        raise ValueError("--allowed-regions needs at least one region code")
    for region in regions:
        if not _REGION_RE.match(region):
            raise ValueError(f"invalid region code in --allowed-regions: {region!r}")
    return tuple(sorted(regions))


def residency_env(policy: str, allowed_regions: tuple[str, ...] | None) -> dict[str, str]:
    """Return the environment variables that select *policy* for the checks."""
    env = {POLICY_ENV_VAR: policy}
    if policy == POLICY_CUSTOM and allowed_regions:
        env[ALLOWED_REGIONS_ENV_VAR] = ",".join(allowed_regions)
    return env


def allowed_regions_from_env(environ: Mapping[str, str], cloud: str = "aws") -> frozenset[str]:
    """Resolve the active region allowlist for *cloud* from *environ* (fails closed).

    Raises ``ValueError`` for a cloud other than ``aws``, ``azure`` or ``gcp``. Bad input
    fails closed: for AWS to the EUSC-only allowlist; for Azure and GCP, which have no
    sovereign partition, to an empty allowlist (nothing is allowed).
    """
    if cloud not in _CLOUDS:
        raise ValueError(f"unsupported cloud for a residency allowlist: {cloud!r}")
    eu_eea = _EU_EEA_BY_CLOUD.get(cloud, EU_EEA_REGIONS)
    strictest = EUSC_REGIONS if cloud == "aws" else frozenset()
    policy = (environ.get(POLICY_ENV_VAR) or "").strip().lower() or DEFAULT_POLICY
    if policy == POLICY_EU_EEA:
        return eu_eea
    if policy == POLICY_CUSTOM:
        try:
            return frozenset(parse_allowed_regions(environ.get(ALLOWED_REGIONS_ENV_VAR, "")))
        except ValueError:
            return strictest
    if policy == POLICY_EUSC:
        # EUSC is an AWS partition: Azure and GCP use their EU/EEA tables.
        return EUSC_REGIONS if cloud == "aws" else eu_eea
    # Any unrecognised value: strictest allowlist.
    return strictest


def _region_unset_warning(
    checkov_output: dict[str, Any],
    *,
    custom_checks_loaded: bool,
    policy_check_id: str,
    resource_re: re.Pattern[str],
    message: str,
) -> str | None:
    """Return *message* when matching resources were scanned but no policy result appeared.

    A provider-region policy check (``policy_check_id``) produces a result only when a region
    was set in the source. Resources of the cloud without any such result, while other EUGUARD_*
    checks did run, mean the region comes from the environment at apply time, which a source
    scan cannot see. With no provider block every EUGUARD check is UNKNOWN and omitted, so a
    live scan (which passes its own --external-checks-dir, ``custom_checks_loaded=True``) may
    legitimately have no EUGUARD_* result. For --checkov-json input tf-eu-guard cannot know
    whether the custom checks were loaded, so with no EUGUARD_* result at all the claim cannot be
    made.
    """
    results = checkov_output.get("results") or {}
    checks = [
        check
        for key in ("passed_checks", "failed_checks", "skipped_checks")
        for check in results.get(key) or []
    ]
    ids = {str(check.get("check_id") or "") for check in checks}
    if policy_check_id in ids:
        return None
    if not custom_checks_loaded and not any(check_id.startswith("EUGUARD_") for check_id in ids):
        # The custom checks did not run (or were not part of this file): the absence of a
        # policy result says nothing about the region.
        return None
    if not any(resource_re.search(str(check.get("resource") or "")) for check in checks):
        return None
    return message


def aws_region_unset_warning(
    checkov_output: dict[str, Any], *, custom_checks_loaded: bool = False
) -> str | None:
    """Return a warning when AWS resources were scanned but no region was ever evaluated."""
    return _region_unset_warning(
        checkov_output,
        custom_checks_loaded=custom_checks_loaded,
        policy_check_id=_POLICY_CHECK_ID,
        resource_re=_AWS_RESOURCE_RE,
        message=(
            'Warning: AWS resources were scanned but no provider "aws" block sets a region, so '
            "the residency checks cannot tell where they deploy (the region comes from the "
            "environment at apply time). Scan a Terraform plan (--iac-type terraform_plan) to "
            "check the real region."
        ),
    )


def gcp_region_unset_warning(
    checkov_output: dict[str, Any], *, custom_checks_loaded: bool = False
) -> str | None:
    """Return a warning when google_* resources were scanned but no location was evaluated."""
    return _region_unset_warning(
        checkov_output,
        custom_checks_loaded=custom_checks_loaded,
        policy_check_id=_GCP_POLICY_CHECK_ID,
        resource_re=_GCP_RESOURCE_RE,
        message=(
            'Warning: google_* resources were scanned but no provider "google" block or '
            "resource sets a region or location, so the residency checks cannot tell where they "
            "deploy (the region comes from the environment, for example GOOGLE_REGION, or from "
            "the provider region at apply time). Scan a Terraform plan "
            "(--iac-type terraform_plan) to check the real location."
        ),
    )
