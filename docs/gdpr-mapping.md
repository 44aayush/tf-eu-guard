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
or key-management governance. This pairs with **NIS2 Art. 21(2)(h)** — the same
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

**Evidence**: Each finding is a concrete confidentiality risk — a way personal data
could be read by an unauthorised party — with a file/line reference for remediation.

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

**Limitations**: "In a timely manner" implies tested restores meeting an RTO — the
checks confirm backups *exist*, not that restore *works within target time*. Pairs
with **NIS2 Art. 21(2)(c)**.

---

### GDPR Article 32(1)(d) — Regularly testing, assessing and evaluating effectiveness

**Legal text** (verbatim, the operative phrase):
> "a process for regularly testing, assessing and evaluating the effectiveness of
> technical and organisational measures for ensuring the security of the processing"

**Infrastructure controls**: No single resource check maps here. Instead, **running
tf-eu-guard in CI is itself (d) evidence** — it is a repeatable, automated process
that regularly assesses the effectiveness of the technical measures above and
produces a timestamped audit trail on every change. This mirrors NIS2 Art. 21(2)(f).

**Limitations**: Automated configuration scanning is one component of (d); it does not
replace penetration testing, DPIAs, or periodic organisational review.

---

### Chapter V (Art. 44) & Recital 83 — International transfers / data residency

**Legal requirement** (Art. 44, paraphrased):
> Any transfer of personal data to a third country (outside the EU/EEA) may take
> place only subject to the conditions of Chapter V (Art. 44–49) — an adequacy
> decision, appropriate safeguards such as Standard Contractual Clauses or Binding
> Corporate Rules, or a specific derogation. Recital 83 additionally ties security
> measures to the risks of processing.

**Infrastructure controls** — deploying resources through a provider pinned to a
non-EU region stores personal data outside the EU/EEA, which is a transfer:

| Check | Control |
|-------|---------|
| EUGUARD_GDPR_001 | AWS provider `region` is in the EU/EEA (**custom** Phase 3 check) |

`EUGUARD_GDPR_001` is a **custom tf-eu-guard check** (added in Phase 3, implemented
in [`tf_eu_guard/checks/gdpr/data_residency.py`](../tf_eu_guard/checks/gdpr/data_residency.py)).
It is a **provider-level** check — data residency is a property of *where* the `aws`
provider deploys, not of any single resource — so it inspects each provider block's
`region`. An EU/EEA region (`eu-*`, or the European Sovereign Cloud `eusc-*`) passes;
a non-EU literal (`us-east-1`, `ap-southeast-2`, …) fails; an unset or still-unresolved
region (`${var.region}`) returns *unknown* rather than a false positive, because the
effective region cannot be decided at scan time.

**Why Art. 44, not Art. 32**: EU data residency is a *lawful-transfer* question
(Chapter V), not a *security-of-processing* control (Art. 32). Mapping it to Art. 44
keeps the legal citation honest.

**Limitations**: Region of deployment is a strong signal but not dispositive of a
lawful transfer analysis — adequacy decisions, SCCs, and BCRs can permit transfers to
non-EU regions. The check flags non-EU regions for review; it does not adjudicate
legality, and it cannot see transfers made by application code or downstream services.

---

## Summary of registry coverage against GDPR Art. 32(1)

| Point | Covered? | Checks |
|-------|----------|--------|
| (a) pseudonymisation / encryption | ✓ | 2 |
| (b) confidentiality / integrity / availability / resilience | ✓ strong | 10 |
| (c) restore availability in a timely manner | ✓ | 3 |
| (d) regularly testing effectiveness | ✓ via CI usage | tool itself |
| Ch. V (Art. 44) transfers / data residency | ✓ custom check | EUGUARD_GDPR_001 |

✓ covered · ◐ partial/planned

> **No overclaiming.** These mappings assume the scanned infrastructure processes
> personal data and address only the *security of processing* (Art. 32). GDPR
> compliance also requires a lawful basis (Art. 6), data-subject rights (Arts. 12–23),
> records of processing (Art. 30), and, where applicable, a DPIA (Art. 35) — none of
> which a configuration linter can evaluate.
