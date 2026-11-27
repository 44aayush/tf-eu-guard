"""AWS region, Azure and GCP location policy tables — the single source of truth.

The residency policies (``eu-eea``, ``eusc``, ``custom``; see
:mod:`tf_eu_guard.residency`) and the Chapter V review checks in
``checks/gdpr/data_residency.py`` (AWS), ``checks/gdpr/azure_residency.py`` (Azure) and
``checks/gdpr/gcp_residency.py`` (GCP) import these tables rather than defining
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
# Source: Microsoft Learn, Azure regions list
# (https://learn.microsoft.com/en-us/azure/reliability/regions-list), verified 2026-11-27.
# Newer EU regions that are not on that list (finlandcentral, greececentral) are
# deliberately left out: they fail the residency policy check, the safe direction for a
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
        "belgiumcentral",  # Brussels
        "denmarkeast",  # Copenhagen
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
        "australiacentral",
        "australiacentral2",
        "brazilsoutheast",
        "chilecentral",
        "indiasouthcentral",
        "indonesiacentral",
        "israelcentral",
        "koreasouth",
        "malaysiawest",
        "mexicocentral",
        "newzealandnorth",
        "qatarcentral",
        "southafricawest",
        "uaecentral",
        "westindia",
        *AZURE_EU_EEA_LOCATIONS,
    }
)


def normalise_azure_location(value: str) -> str:
    """Lower-case *value* and drop spaces, hyphens and underscores."""
    return re.sub(r"[\s_-]+", "", value).lower()


# Source: Google Cloud regions and zones
# (https://docs.cloud.google.com/compute/docs/regions-zones), verified 2026-11-27.
# GCP locations. Regions, zones and multi-regions are compared in normalised
# form (lower case; a zone maps to its region; "EU" == "eu"). Dual-regions such
# as `eur4` could not be verified, so they are left out: they fail the
# residency policy check (fail closed) and stay undecided for the Chapter V
# review. A classification table, not a legal conclusion.
GCP_EU_EEA_LOCATIONS = frozenset(
    {
        "europe-west1",  # Belgium
        "europe-west3",  # Frankfurt
        "europe-west4",  # Netherlands
        "europe-west8",  # Milan
        "europe-west9",  # Paris
        "europe-west10",  # Berlin
        "europe-west12",  # Turin
        "europe-north1",  # Finland
        "europe-north2",  # Stockholm
        "europe-central2",  # Warsaw
        "europe-southwest1",  # Madrid
        "eu",  # multi-region
    }
)

# EU/EEA locations plus known third-country ones (London and Zurich are GDPR
# third countries). Locations not listed stay UNKNOWN for the Chapter V check.
GCP_KNOWN_LOCATIONS = frozenset(
    {
        "europe-west2",  # London
        "europe-west6",  # Zurich
        "us",
        "asia",
        "us-central1",
        "us-east1",
        "us-east4",
        "us-east5",
        "us-south1",
        "us-west1",
        "us-west2",
        "us-west3",
        "us-west4",
        "northamerica-northeast1",
        "northamerica-northeast2",
        "southamerica-east1",
        "southamerica-west1",
        "asia-east1",
        "asia-east2",
        "asia-northeast1",
        "asia-northeast2",
        "asia-northeast3",
        "asia-south1",
        "asia-south2",
        "asia-southeast1",
        "asia-southeast2",
        "australia-southeast1",
        "australia-southeast2",
        "me-west1",
        "me-central1",
        "me-central2",
        "africa-south1",
        "northamerica-south1",
        "asia-southeast3",
        *GCP_EU_EEA_LOCATIONS,
    }
)

_GCP_ZONE_RE = re.compile(r"^([a-z]+-[a-z]+[0-9]+)-[a-z]$")


def normalise_gcp_location(value: str) -> str:
    """Lower-case *value* and map a zone (``europe-west4-a``) to its region."""
    location = value.strip().lower()
    zone = _GCP_ZONE_RE.match(location)
    return zone.group(1) if zone else location


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
