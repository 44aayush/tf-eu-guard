"""AWS region policy for EU data residency — the single source of truth.

This project is based on the AWS European Sovereign Cloud: only EUSC regions
are acceptable deployment targets. The :class:`EUGUARD_GDPR_001` check
(``checks/gdpr/data_residency.py``) imports this table rather than defining
it inline, so the policy is reviewable — and pin-able by tests — on its own.
"""

# The only acceptable deployment targets: regions of the AWS European
# Sovereign Cloud. Verified against botocore's partition data on 2026-09-08
# (the EUSC partition's region code is ``eusc-de-east-1`` — Brandenburg,
# Germany). When AWS launches a second EUSC region, add it here — a missing
# region fails closed until then.
EUSC_REGIONS = frozenset({
    "eusc-de-east-1",  # AWS European Sovereign Cloud (Brandenburg, Germany)
})

# Regions deliberately NOT on the allowlist, kept documented because they are
# the codes most likely to be mistaken for acceptable targets (no separate
# enforcement needed — anything off the allowlist fails):
#   eu-central-1..2, eu-west-1..3, eu-north-1, eu-south-1..2
#                     Commercial "Europe" regions — GDPR-permissible for EU
#                     residents, but NOT part of the Sovereign Cloud.
#   eu-west-2         London, United Kingdom — GDPR third country (Brexit).
#   eu-central-2      Zurich, Switzerland — GDPR third country (never a member).
#   eu-isoe-west-1    AWS ISO-E — air-gapped partition, not commercial AWS.
