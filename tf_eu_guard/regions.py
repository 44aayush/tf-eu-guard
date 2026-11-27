"""AWS region policy tables — the single source of truth.

The residency policies (``eu-eea``, ``eusc``, ``custom``; see
:mod:`tf_eu_guard.residency`) and the Chapter V review checks in
``checks/gdpr/data_residency.py`` import these tables rather than defining
them inline, so the policy is reviewable — and pin-able by tests — on its own.
"""

import re

# Regions of the AWS European
# Sovereign Cloud. Verified against botocore's partition data on 2026-09-08
# (the EUSC partition's region code is ``eusc-de-east-1`` — Brandenburg,
# Germany). When AWS launches a second EUSC region, add it here — a missing
# region fails closed until then.
EUSC_REGIONS = frozenset(
    {
        "eusc-de-east-1",  # AWS European Sovereign Cloud (Brandenburg, Germany)
    }
)

# EU/EEA regions: commercial ones plus EUSC. This is the default residency
# policy (``eu-eea``); the ``eusc`` policy narrows it to EUSC_REGIONS.
EU_EEA_REGIONS = (
    frozenset(
        {
            "eu-central-1",  # Frankfurt, Germany
            "eu-north-1",  # Stockholm, Sweden
            "eu-south-1",  # Milan, Italy
            "eu-south-2",  # Aragon, Spain
            "eu-west-1",  # Dublin, Ireland
            "eu-west-3",  # Paris, France
        }
    )
    | EUSC_REGIONS
)

# Azure locations. Azure `location` values are compared in normalised form
# (lower case, no spaces, hyphens or underscores): "West Europe" == "westeurope".
# Newer EU regions that could not be verified from an authoritative source
# (belgiumcentral, denmarkeast, finlandcentral, greececentral) are deliberately
# left out: they fail the residency policy check, the safe direction for a
# fail-closed gate, until they are verified, and they are not classified as
# third countries for the Chapter V review.
AZURE_EU_EEA_LOCATIONS = frozenset(
    {
        "northeurope",  # Ireland
        "westeurope",  # Netherlands
        "francecentral",
        "francesouth",
        "germanywestcentral",
        "germanynorth",
        "swedencentral",
        "swedensouth",
        "italynorth",
        "polandcentral",
        "spaincentral",
        "norwayeast",
        "norwaywest",
        "austriaeast",
    }
)

# EU/EEA locations plus known third-country ones (the UK and Switzerland are
# GDPR third countries). A classification table, not a legal conclusion;
# locations not listed stay UNKNOWN for the Chapter V check.
AZURE_KNOWN_LOCATIONS = frozenset(
    {
        "uksouth",
        "ukwest",
        "switzerlandnorth",
        "switzerlandwest",
        "eastus",
        "eastus2",
        "westus",
        "westus2",
        "westus3",
        "centralus",
        "northcentralus",
        "southcentralus",
        "westcentralus",
        "canadacentral",
        "canadaeast",
        "brazilsouth",
        "eastasia",
        "southeastasia",
        "japaneast",
        "japanwest",
        "australiaeast",
        "australiasoutheast",
        "centralindia",
        "southindia",
        "koreacentral",
        "uaenorth",
        "southafricanorth",
        *AZURE_EU_EEA_LOCATIONS,
    }
)


def normalise_azure_location(value: str) -> str:
    """Lower-case *value* and drop spaces, hyphens and underscores."""
    return re.sub(r"[\s_-]+", "", value).lower()


# Regions AWS lists that are deliberately NOT classified as known third
# countries. eu-isoe-west-1 is an isolated (ISO-E) partition region located in
# Europe; calling it a third-country transfer would be an unsupported legal
# claim, so GDPR_002/003 leave it UNKNOWN. It is on no residency allowlist, so
# the residency policy checks (POLICY_001/002) still FAIL it. Listed here so
# tools/check_region_drift.py treats it as accounted for.
UNCLASSIFIED_AWS_REGIONS = frozenset({"eu-isoe-west-1"})

# Keep in sync with botocore: tools/check_region_drift.py reports drift.
# Region codes known to AWS but outside the EU/EEA allowlist above. This is a
# classification table, not a legal conclusion: a failed transfer-review
# check means that Chapter V safeguards need review. Region codes not known
# here (including unresolved variables and malformed strings) remain UNKNOWN
# for that check rather than being labelled third countries.
KNOWN_AWS_REGIONS = frozenset(
    {
        "af-south-1",
        "ap-east-1",
        "ap-east-2",  # Taipei
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
        "ap-southeast-6",  # New Zealand
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
        "us-isob-west-1",
        "us-isof-east-1",
        "us-isof-south-1",
        "us-isob-east-1",
        "us-west-1",
        "us-west-2",
        "eu-central-2",  # Zurich, Switzerland
        "eu-west-2",  # London, United Kingdom
        *EU_EEA_REGIONS,
    }
)

# Regions deliberately NOT on the allowlist, kept documented because they are
# the codes most likely to be mistaken for acceptable targets (no separate
# enforcement needed — anything off the allowlist fails):
#   eu-central-1..2, eu-west-1..3, eu-north-1, eu-south-1..2
#                     Commercial "Europe" regions — GDPR-permissible for EU
#                     residents, but NOT part of the Sovereign Cloud.
#   eu-west-2         London, United Kingdom — GDPR third country (Brexit).
#   eu-central-2      Zurich, Switzerland — GDPR third country (never a member).
#   eu-isoe-west-1    AWS ISO-E — air-gapped partition, not commercial AWS.
