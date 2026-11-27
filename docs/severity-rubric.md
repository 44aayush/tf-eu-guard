# Severity rubric

The registry authors severity (Checkov leaves `severity` null). This page states the rule behind the
severities of four families of checks, so that two checks that guard the same risk do not end up at
different levels. `tests/test_registry_rubric.py` pins exactly the IDs listed here. Checks that are not
listed are outside the rubric for now: their severities are authored case by case and are not covered by
this page.

Severity is a prioritisation signal for a reviewer. It is not a legal finding, and a mapped article is a
hedged pointer to a possible relevance, not a verdict.

## Families

### Public exposure of a data store or an admin port: CRITICAL

The configuration makes a data store or an administrative port reachable by anyone on the internet, so
a single misconfiguration is enough for exposure.

`CKV_AWS_17`, `CKV_AWS_20`, `CKV_AWS_70`, `CKV_AWS_87`, `CKV_AWS_24`, `CKV_AWS_25`, `CKV_AWS_38`, `CKV_AZURE_11`, `CKV_GCP_11`, `CKV_GCP_28`, `CKV_GCP_88`

`CKV_AWS_24` (SSH), `CKV_AWS_25` (RDP) and `CKV_AWS_38` (EKS public endpoint open to 0.0.0.0/0) are CRITICAL
because a world-open admin port or endpoint is directly exposed. They were HIGH before this rubric.

### Public-network guardrails: HIGH

Controls that defend in depth against exposure (public-access blocks, private endpoints, restricted
control planes). A failing guardrail does not by itself expose data, but removes a layer that would
contain a mistake elsewhere. `CKV_AZURE_59` (the storage-account public-access switch) is the Azure counterpart
of the S3 block-public settings and is HIGH for that reason; it was CRITICAL before this rubric.

`CKV2_AWS_6`, `CKV_AWS_53`, `CKV_AWS_54`, `CKV_AWS_55`, `CKV_AWS_56`, `CKV_AZURE_59`, `CKV_AZURE_139`, `CKV_AZURE_160`, `CKV_AZURE_48`, `CKV_AZURE_53`, `CKV_GCP_18`

### Data-store encryption at rest: HIGH

Data stores that hold data without any encryption at rest.

`CKV_AWS_16`, `CKV_AWS_3`, `CKV_AWS_96`, `CKV_AWS_5`, `CKV_AWS_44`

### Customer-managed key instead of a provider-managed key: MEDIUM

The data is already encrypted with a provider-managed key. A customer-managed key (CMK) adds key-control
depth (rotation policy, access policy, revocation), which GDPR Art. 32(1)(a) does not itself require, so
these checks are MEDIUM.

`CKV_AWS_119`, `CKV_AWS_147`, `CKV_AWS_149`, `CKV_AWS_186`, `CKV_AWS_189`, `CKV_AWS_191`, `CKV_AWS_224`, `CKV_AWS_247`, `CKV_AWS_280`, `CKV_AWS_327`, `CKV_AWS_347`, `CKV_AWS_35`

`CKV_AWS_119`, `CKV_AWS_147`, `CKV_AWS_149`, `CKV_AWS_247`, `CKV_AWS_327`, `CKV_AWS_347` and
`CKV_AWS_35` were HIGH before this rubric. A team that treats a CMK as mandatory can restore the old level
with `severity_overrides` (see [configuration.md](configuration.md)).
