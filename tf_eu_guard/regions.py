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

# Commercial AWS regions in the EU/EEA. These satisfy the GDPR geographic
# baseline, but are deliberately not in EUSC_REGIONS: the project's separate
# sovereignty policy requires the European Sovereign Cloud.
EU_EEA_REGIONS = frozenset({
    "eu-central-1",  # Frankfurt, Germany
    "eu-north-1",    # Stockholm, Sweden
    "eu-south-1",    # Milan, Italy
    "eu-south-2",    # Aragon, Spain
    "eu-west-1",     # Dublin, Ireland
    "eu-west-3",     # Paris, France
}) | EUSC_REGIONS

# Region codes known to AWS but outside the EU/EEA allowlist above. This is a
# classification table, not a legal conclusion: a failed transfer-review
# check means that Chapter V safeguards need review. Region codes not known
# here (including unresolved variables and malformed strings) remain UNKNOWN
# for that check rather than being labelled third countries.
KNOWN_AWS_REGIONS = frozenset({
    "af-south-1",
    "ap-east-1",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-northeast-3",
    "ap-south-1",
    "ap-south-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-southeast-3",
    "ap-southeast-4",
    "ap-southeast-5",
    "ap-southeast-7",
    "ca-central-1",
    "ca-west-1",
    "cn-north-1",
    "cn-northwest-1",
    "il-central-1",
    "me-central-1",
    "me-south-1",
    "mx-central-1",
    "sa-east-1",
    "us-east-1",
    "us-east-2",
    "us-gov-east-1",
    "us-gov-west-1",
    "us-iso-east-1",
    "us-iso-west-1",
    "us-isob-east-1",
    "us-west-1",
    "us-west-2",
    "eu-central-2",  # Zurich, Switzerland
    "eu-west-2",     # London, United Kingdom
    *EU_EEA_REGIONS,
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
