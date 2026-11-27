# Severity rubric

The registry authors severity (Checkov leaves `severity` null). This page states the rule behind the
severities of five families of checks, so that two checks that guard the same risk do not end up at
different levels. `tests/test_registry_rubric.py` pins exactly the IDs listed here. Checks that are not
listed are outside the rubric for now: their severities are authored case by case and are not covered by
this page.

Severity is a prioritisation signal for a reviewer. It is not a legal finding, and a mapped article is a
hedged pointer to a possible relevance, not a verdict.

## Families

### Public exposure of a data store or an admin port: CRITICAL

The configuration makes a data store or an administrative port reachable by anyone on the internet, so
a single misconfiguration is enough for exposure.

`CKV_AWS_17`, `CKV_AWS_20`, `CKV_AWS_70`, `CKV_AWS_87`, `CKV_AWS_24`, `CKV_AWS_25`, `CKV_AWS_38`, `CKV_AZURE_11`, `CKV_GCP_11`, `CKV_GCP_18`, `CKV_GCP_28`, `CKV_GCP_88`

`CKV_AWS_24` (SSH), `CKV_AWS_25` (RDP), `CKV_AWS_38` (EKS public endpoint open to 0.0.0.0/0) and
`CKV_GCP_18` (GKE control plane reachable from 0.0.0.0/0) are CRITICAL because a world-open admin port or
endpoint is directly exposed. They were HIGH before this rubric. The same control on two clouds belongs to the
same family.

### Public-network guardrails: HIGH

Controls that defend in depth against exposure (public-access blocks, private endpoints). A failing guardrail does not by itself expose data, but removes a layer that would
contain a mistake elsewhere. `CKV_AZURE_59` (the storage-account public-access switch) is the Azure counterpart
of the S3 block-public settings and is HIGH for that reason; it was CRITICAL before this rubric.

`CKV2_AWS_6`, `CKV_AWS_53`, `CKV_AWS_54`, `CKV_AWS_55`, `CKV_AWS_56`, `CKV_AZURE_59`, `CKV_AZURE_139`, `CKV_AZURE_48`, `CKV_AZURE_53`

### Data-store encryption at rest: HIGH

Data stores that hold data without any encryption at rest.

`CKV_AWS_16`, `CKV_AWS_3`, `CKV_AWS_96`, `CKV_AWS_5`, `CKV_AWS_44`, `CKV_AWS_26`

`CKV_AWS_26` (SNS topic encryption) is in this family because the SNS documentation describes server-side encryption
as something you enable on a topic with a KMS key, and does not state that topics are encrypted by default
(<https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html>).

### Customer-managed key instead of a provider-managed key: MEDIUM

The data is already encrypted with a provider-managed key. A customer-managed key (CMK) adds key-control
depth (rotation policy, access policy, revocation), which GDPR Art. 32(1)(a) does not itself require, so
these checks are MEDIUM.

`CKV_AWS_119`, `CKV_AWS_147`, `CKV_AWS_149`, `CKV_AWS_186`, `CKV_AWS_189`, `CKV_AWS_191`, `CKV_AWS_224`, `CKV_AWS_247`, `CKV_AWS_280`, `CKV_AWS_327`, `CKV_AWS_347`, `CKV_AWS_35`, `CKV_AWS_173`, `CKV_AWS_145`, `CKV_AWS_136`, `CKV_GCP_38`

`CKV_AWS_119`, `CKV_AWS_147`, `CKV_AWS_149`, `CKV_AWS_247`, `CKV_AWS_327`, `CKV_AWS_347` and
`CKV_AWS_35` were HIGH before this rubric. A team that treats a CMK as mandatory can restore the old level
with `severity_overrides` (see [configuration.md](configuration.md)).

`CKV_AWS_173`, `CKV_AWS_145`, `CKV_AWS_136` and `CKV_GCP_38` were HIGH before this rubric. The provider
documentation states that each service encrypts at rest by default with a provider-managed key: Lambda environment
variables (<https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html>), S3 buckets with SSE-S3
(<https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html>), ECR repositories
(<https://docs.aws.amazon.com/AmazonECR/latest/userguide/encryption-at-rest.html>) and Compute Engine disks
(<https://docs.cloud.google.com/docs/security/encryption/default-encryption>).

### Web port open to the internet: MEDIUM

Port 80 open to the internet. A public web tier is often intended to accept plain HTTP (for a redirect to HTTPS), and
the administrative ports are already in the CRITICAL exposure family, so these checks are MEDIUM.

`CKV_AWS_260`, `CKV_AZURE_160`

`CKV_AZURE_160` was HIGH before this rubric.

