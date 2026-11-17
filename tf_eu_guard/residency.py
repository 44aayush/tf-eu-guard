"""Residency policy selection shared by the CLI and the custom Checkov checks.

The custom checks run inside a Checkov subprocess, so the CLI hands the chosen
policy over through two environment variables that only
:func:`tf_eu_guard.checkov.process.run_checkov` sets explicitly (the ambient
values are scrubbed by ``checkov_environment``). The checks read them at scan
time with :func:`allowed_regions_from_env`.

``eu-eea``  every commercial EU/EEA region plus the AWS European Sovereign Cloud
``eusc``    only the AWS European Sovereign Cloud (the 0.7.x behaviour)
``custom``  an explicit allowlist from ``--allowed-regions``

Direct Checkov use (no CLI) leaves both variables unset and gets ``eu-eea``.
An unrecognised policy value, or ``custom`` with no usable regions, fails
closed to the EUSC-only allowlist rather than silently widening the policy.
"""

import re
from collections.abc import Mapping

from tf_eu_guard.regions import EU_EEA_REGIONS, EUSC_REGIONS

POLICY_ENV_VAR = "TF_EU_GUARD_RESIDENCY_POLICY"
ALLOWED_REGIONS_ENV_VAR = "TF_EU_GUARD_ALLOWED_REGIONS"
RESIDENCY_ENV_VARS = (POLICY_ENV_VAR, ALLOWED_REGIONS_ENV_VAR)

POLICY_EU_EEA = "eu-eea"
POLICY_EUSC = "eusc"
POLICY_CUSTOM = "custom"
RESIDENCY_POLICIES = (POLICY_EU_EEA, POLICY_EUSC, POLICY_CUSTOM)
DEFAULT_POLICY = POLICY_EU_EEA

_REGION_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


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


def allowed_regions_from_env(environ: Mapping[str, str]) -> frozenset[str]:
    """Resolve the active region allowlist from *environ* (fails closed)."""
    policy = (environ.get(POLICY_ENV_VAR) or "").strip().lower() or DEFAULT_POLICY
    if policy == POLICY_EU_EEA:
        return EU_EEA_REGIONS
    if policy == POLICY_CUSTOM:
        try:
            return frozenset(parse_allowed_regions(environ.get(ALLOWED_REGIONS_ENV_VAR, "")))
        except ValueError:
            return EUSC_REGIONS
    # "eusc" and any unrecognised value: strictest allowlist.
    return EUSC_REGIONS
