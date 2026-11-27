# GDPR Article 32 Mapping

**Regulation**: Regulation (EU) 2016/679 (GDPR), Article 32 — *Security of
processing*.

Article 32(1) requires controllers and processors to implement appropriate technical
and organisational measures to ensure a level of security appropriate to the risk,
and lists, *inter alia*, points (a)–(d). Article 32(2) requires that the risk
assessment account for the risks of accidental or unlawful destruction, loss,
alteration, or unauthorised disclosure of / access to personal data.

This document maps the subset of Article 32(1) that is **verifiable from Terraform
infrastructure configuration** to the Checkov checks in
[`registry-aws.yaml`](../tf_eu_guard/mapping/registry-aws.yaml). See
[`check-mapping-table.md`](check-mapping-table.md) for the full matrix.

> **Scope & honesty.** Article 32 applies specifically to the security of **personal
> data** processing. tf-eu-guard cannot know *which* resources hold personal data, so
> these mappings assume the scanned infrastructure processes personal data (the
> conservative assumption for a compliance gate). The tool verifies configuration; it
> does not verify lawful basis, data-subject rights, DPIAs, or records of processing —
> those are separate GDPR obligations.

---

### GDPR Article 32(1)(a) — Pseudonymisation and encryption of personal data

**Legal text** (verbatim, the operative phrase):
> "the pseudonymisation and encryption of personal data"

**Infrastructure controls** — encryption of personal data at rest:

| Check | Control |
|-------|---------|
| CKV_AWS_16 | RDS storage encrypted at rest (KMS) |
| CKV_AWS_145 | S3 buckets encrypted with KMS by default |

**Evidence**: Encryption is one of only two measures Article 32(1) names explicitly,
which is why these are mapped with high confidence. A green result shows personal
data at rest is protected by managed-key encryption.

**Limitations**: Covers encryption at rest for the primary data stores only. Does not
cover pseudonymisation (an application-layer design choice), encryption in transit,
or key-management governance. This pairs with **NIS2 Art. 21(2)(h)**; the same
checks satisfy both frameworks.

---

### GDPR Article 32(1)(b) — Confidentiality, integrity, availability and resilience

**Legal text** (verbatim, the operative phrase):
> "the ability to ensure the ongoing confidentiality, integrity, availability and
> resilience of processing systems and services"

**Infrastructure controls** — preventing unauthorised access and public exposure of
personal data (the *confidentiality* limb, primarily):

| Check | Control |
|-------|---------|
| CKV_AWS_20 | S3 bucket not public-readable |
| CKV_AWS_53 | S3 block-public-ACLs guardrail enabled |
| CKV2_AWS_6 | S3 public access block present |
| CKV_AWS_17 | RDS not publicly accessible |
| CKV_AWS_130 | Subnets do not auto-assign public IPs |
| CKV_AWS_161 | RDS uses IAM authentication (access integrity) |
| CKV_AWS_287 | IAM policy does not allow credential exposure |
| CKV_AWS_288 | IAM policy does not allow data exfiltration |
| CKV_AWS_286 | IAM policy does not allow privilege escalation |
| CKV_AWS_62 | No `*:*` full-admin IAM policy |

**Evidence**: Each finding is a concrete confidentiality risk, a way personal data
could be read by an unauthorised party, with a file/line reference for remediation.

**Limitations**: The *availability* and *resilience* limbs of (b) overlap with (c)
below; here we map (b) mainly to the confidentiality controls. Network-layer controls
(security-group egress, default SG lockdown) are expansion candidates.

---

### GDPR Article 32(1)(c) — Ability to restore availability and access in a timely manner

**Legal text** (verbatim, the operative phrase):
> "the ability to restore the availability and access to personal data in a timely
> manner in the event of a physical or technical incident"

**Infrastructure controls** — recoverability of personal data:

| Check | Control |
|-------|---------|
| CKV_AWS_133 | RDS backup retention configured |
| CKV_AWS_293 | RDS deletion protection enabled |
| CKV_AWS_21 | S3 object versioning enabled |

**Evidence**: Backups and versioning provide the restore points (c) demands;
deletion protection prevents a single action from destroying the ability to restore.

**Limitations**: "In a timely manner" implies tested restores meeting an RTO. The
checks confirm backups *exist*, not that restore *works within target time*. Pairs
with **NIS2 Art. 21(2)(c)**.

---

### GDPR Article 32(1)(d) — Regularly testing, assessing and evaluating effectiveness

**Legal text** (verbatim, the operative phrase):
> "a process for regularly testing, assessing and evaluating the effectiveness of
> technical and organisational measures for ensuring the security of the processing"

**Infrastructure controls**: No single resource check maps here. Instead, running
tf-eu-guard in CI is itself (d) evidence. It is a repeatable, automated process
that regularly assesses the effectiveness of the technical measures above and
produces a timestamped audit trail on every change. This mirrors NIS2 Art. 21(2)(f).

**Limitations**: Automated configuration scanning is one component of (d); it does not
replace penetration testing, DPIAs, or periodic organisational review.

---

### Chapter V (Art. 44) & Recital 83 — International transfers / data residency

**Legal requirement** (Art. 44, paraphrased):
> Any transfer of personal data to a third country (outside the EU/EEA) may take
> place only subject to the conditions of Chapter V (Art. 44–49): an adequacy
> decision, appropriate safeguards such as Standard Contractual Clauses or Binding
> Corporate Rules, or a specific derogation. Recital 83 additionally ties security
> measures to the risks of processing.

**Infrastructure controls** — the region checks deliberately separate a
configurable residency *policy* from the GDPR Chapter V review signal:

| Check | Control |
|-------|---------|
| EUGUARD_POLICY_001 | AWS provider `region` is within the configured residency policy (**project policy** custom check) |
| EUGUARD_POLICY_002 | Resource-level regions (`region` argument, replicas, copy destinations) are within the policy (**project policy** custom check) |
| EUGUARD_GDPR_001 | **Deprecated** alias of EUGUARD_POLICY_001 so 0.7.x `--checkov-json` files still map; removed in the next release |
| EUGUARD_GDPR_002 | A known AWS provider region outside the EU/EEA receives a Chapter V review signal (**custom** check) |
| EUGUARD_GDPR_003 | A known resource-level region outside the EU/EEA receives a Chapter V review signal (**custom** check) |
| EUGUARD_POLICY_003 | Azure `azurerm_*` resource `location` is within the configured residency policy (**project policy** custom check) |
| EUGUARD_GDPR_004 | A known Azure `location` outside the EU/EEA (including the UK and Switzerland) receives a Chapter V review signal (**custom** check) |

These are **custom tf-eu-guard checks**. The AWS ones are implemented in
[`tf_eu_guard/checks/gdpr/data_residency.py`](../tf_eu_guard/checks/gdpr/data_residency.py), the Azure ones in
[`tf_eu_guard/checks/gdpr/azure_residency.py`](../tf_eu_guard/checks/gdpr/azure_residency.py) (below).
The `*_001`/`*_002` provider checks inspect each `provider "aws"` block's
`region`. Since AWS provider 6.0 most resources also accept a top-level
`region` argument, and replication settings place data elsewhere regardless of
the provider, so `EUGUARD_POLICY_002` and `EUGUARD_GDPR_003` inspect: the
top-level `region` of any `aws_*` resource, `aws_dynamodb_table`
`replica[].region_name`, `aws_secretsmanager_secret` `replica[].region`,
`aws_ecr_replication_configuration` destination `region`, and
`aws_backup_plan` `rule.copy_action.destination_vault_arn` (region parsed from
the ARN; an unresolved ARN is skipped). `aws_s3_bucket_replication_configuration`
destinations are bucket ARNs whose region is not resolvable statically and are
**not** evaluated.

**Azure** (`EUGUARD_POLICY_003` / `EUGUARD_GDPR_004`, in
[`tf_eu_guard/checks/gdpr/azure_residency.py`](../tf_eu_guard/checks/gdpr/azure_residency.py))
evaluate the `location` argument of every `azurerm_*` resource, compared in
normalised form (`West Europe` equals `westeurope`). The policy check is fail-closed
against a maintained EU/EEA table: a newer EU location that is not yet verified
(for example `belgiumcentral`) fails the policy check and stays *unknown* for the Chapter V
signal, which fails only for known third-country locations. The Azure checks use the
same `--residency-policy` flag: `eu-eea` (default) and `eusc` both use the Azure EU/EEA
table, since the Sovereign Cloud is an AWS partition, and `custom` applies the same
allowlist to every cloud. GCP locations are not evaluated.

**Residency policy** (`--residency-policy`, GitHub Action input
`residency-policy`): `eu-eea` (default) allows the EU/EEA commercial regions
plus the AWS European Sovereign Cloud; `eusc` allows only `eusc-de-east-1` (the
0.7.x behaviour); `custom` uses `--allowed-regions REGION[,REGION...]`. The CLI
hands the policy to the Checkov subprocess through the
`TF_EU_GUARD_RESIDENCY_POLICY` / `TF_EU_GUARD_ALLOWED_REGIONS` environment
variables (ambient values are discarded); direct Checkov use without them
defaults to `eu-eea`, and an invalid value fails closed to the EUSC-only
allowlist. With `--checkov-json` the results are pre-computed, so the policy
flags are ignored and a warning is printed.

The policy checks are **fail-closed**: a region off the allowlist fails,
including `eu-west-2` (London) and `eu-central-2` (Zurich), which are third
countries, and an unresolved region reference (`var.region` with no default),
because a target that cannot be proven statically is flagged for review. An
*unset* provider region (inherited at apply time) returns *unknown*, as does a
resource with no region information. The mapping is `POLICY Policy
RESIDENCY-001`, not GDPR Art. 44.

`EUGUARD_GDPR_002` / `EUGUARD_GDPR_003` use a separate known-region table and
fail only for known AWS regions outside the EU/EEA, such as `us-east-1`.
EU/EEA and EUSC regions pass; unknown or unresolved values remain unknown
rather than being labelled third countries. A provider in `eu-central-1` with
a DynamoDB replica in `us-east-1` therefore produces the policy finding and a
hedged Art. 44 review signal for the table.

**Why Art. 44, not Art. 32**: a known third-country transfer review is a
*lawful-transfer* question (Chapter V) and falls outside the *security-of-processing* controls
of Art. 32. Mapping only `EUGUARD_GDPR_002` / `EUGUARD_GDPR_003` to Art. 44 keeps the legal citation
honest: `EUGUARD_POLICY_001` / `_002` enforce a separate policy that can be *stricter* than the Art. 44
baseline (under `eusc`, which rejects commercial EU/EEA regions), so such a finding is
a policy deviation, not a legal violation. The Art. 44 finding is likewise a
review signal, not a definitive conclusion about whether a transfer occurs or
which Chapter V mechanism applies.

**Limitations**: Region of deployment is a strong signal but not dispositive of a
lawful transfer analysis, because adequacy decisions, SCCs, and BCRs can permit transfers to
non-EU regions. The check flags out-of-policy regions for review; it does not adjudicate
legality, and it cannot see transfers made by application code or downstream services.

---

## Summary of registry coverage against GDPR Art. 32(1)

| Point | Covered? | Checks |
|-------|----------|--------|
| (a) pseudonymisation / encryption | ◐ partial (encryption only) | 2 |
| (b) confidentiality / integrity / availability / resilience | ✓ strong | 10 |
| (c) restore availability in a timely manner | ✓ | 3 |
| (d) regularly testing effectiveness | ◐ process evidence (CI usage) | tool itself |
| Ch. V (Art. 44) transfers / data residency | ✓ custom checks | EUGUARD_GDPR_002, EUGUARD_GDPR_003 |

✓ covered · ◐ partial/planned

> **No overclaiming.** These mappings assume the scanned infrastructure processes
> personal data and address only the *security of processing* (Art. 32). GDPR
> compliance also requires a lawful basis (Art. 6), data-subject rights (Arts. 12–23),
> records of processing (Art. 30), and, where applicable, a DPIA (Art. 35) — none of
> which a configuration linter can evaluate.
