# NIS2 Article 21 Mapping

**Regulation**: Directive (EU) 2022/2555 (NIS2), Article 21 — *Cybersecurity
risk-management measures*. Transposition deadline: 17 October 2024.

Article 21(1) requires essential and important entities to take *appropriate and
proportionate* technical, operational and organisational measures, taking into
account the state of the art, cost of implementation, and the entity's size and
exposure. Article 21(2) lists the minimum measures, points (a)–(j).

This document maps the subset of those measures that are **verifiable from
Terraform infrastructure configuration** to the Checkov checks in
[`registry-aws.yaml`](../tf_eu_guard/mapping/registry-aws.yaml). See
[`check-mapping-table.md`](check-mapping-table.md) for the full matrix.

> **Scope & honesty.** tf-eu-guard verifies *infrastructure configuration only*.
> NIS2 Article 21 is largely about **policies and procedures** — governance,
> training, supply-chain contracts, incident-response playbooks — which no linter
> can assess. Passing every check below is necessary evidence, not sufficient proof
> of compliance. Points (a) risk analysis, (d) supply-chain security, and (g) cyber
> hygiene/training are organisational and are intentionally out of scope here.

---

### NIS2 Article 21(2)(b) — Incident handling

**Legal requirement** (paraphrased):
> Measures for the detection, analysis, containment, response to, and recovery from
> cybersecurity incidents.

**Infrastructure controls** — you cannot analyse an incident you never recorded.
The linter checks that the telemetry needed for detection and forensics exists:

| Check | Control |
|-------|---------|
| CKV_AWS_18 | S3 server access logging enabled |
| CKV_AWS_129 | RDS engine logs exported to CloudWatch |
| CKV2_AWS_11 | VPC flow logging enabled on all VPCs |

**Evidence**: A green result demonstrates that object-access, database, and
network-flow telemetry is being captured — the raw material for detecting and
reconstructing an incident.

**Limitations**: Logging ≠ monitoring. NIS2 (b) also expects alerting, triage, and a
documented response process (detection tooling such as GuardDuty, SIEM correlation,
on-call procedures). Those are not represented by these checks. The reference stack
has no CloudTrail/GuardDuty resources, so those controls appear as *absent* rather
than *failing*.

---

### NIS2 Article 21(2)(c) — Business continuity, backup management and disaster recovery

**Legal requirement** (paraphrased):
> Business continuity measures such as backup management and disaster recovery, and
> crisis management.

**Infrastructure controls**:

| Check | Control |
|-------|---------|
| CKV_AWS_133 | RDS backup retention configured (point-in-time restore) |
| CKV_AWS_293 | RDS deletion protection enabled |
| CKV_AWS_21 | S3 object versioning enabled |

**Evidence**: Non-zero RDS backup retention and S3 versioning give demonstrable
recovery points; deletion protection prevents a single mistaken `destroy` from
causing irreversible data loss.

**Limitations**: The checks confirm that backups/versioning are *enabled*, not that
restores are *tested*, that RPO/RTO targets are met, or that backups are stored in a
separate failure domain. Multi-AZ (CKV_AWS_157) and cross-region replication
(CKV_AWS_144) are strong (c) candidates not yet in the registry — see the mapping
table's expansion list.

---

### NIS2 Article 21(2)(e) — Security in acquisition, development and maintenance

**Legal requirement** (paraphrased):
> Security in network and information systems acquisition, development and
> maintenance, including vulnerability handling and disclosure.

**Infrastructure controls** — the IaC-relevant slice covers secure development
practice in the Terraform itself, plus timely patching of managed components:

| Check | Control |
|-------|---------|
| EUGUARD_NIS2_001 | No hardcoded secrets in Terraform IaC (**custom** Phase 3 check) |
| CKV_AWS_226 (candidate) | RDS auto minor version upgrades — timely patching |

`EUGUARD_NIS2_001` is a **custom tf-eu-guard check** (added in Phase 3, implemented
in [`tf_eu_guard/checks/nis2/secrets_in_code.py`](../tf_eu_guard/checks/nis2/secrets_in_code.py))
that fails when a literal credential is inlined in a resource argument — e.g. an
`aws_db_instance` `password`, an `aws_rds_cluster` `master_password`, or an
`aws_elasticache_replication_group` `auth_token` — instead of being sourced from a
secrets manager or a `sensitive` variable resolved at apply time. Committing secrets
to code is a canonical insecure-development failure; keeping them out of the IaC is
precisely the "security in ... development" that (e) requires. `CKV_AWS_226`
(patching) remains a documented **expansion candidate** (not yet in the registry).

**Evidence / limitations**: Running tf-eu-guard *is itself* part of secure
development — it is a security gate in the IaC pipeline. But (e) also covers SDLC
process, dependency/vulnerability management, and disclosure handling, which are out
of scope for a configuration linter.

---

### NIS2 Article 21(2)(f) — Assessing the effectiveness of risk-management measures

**Legal requirement** (paraphrased):
> Policies and procedures to assess the effectiveness of cybersecurity
> risk-management measures.

**Infrastructure controls**: No single resource check maps here. Instead, **the tool
itself provides (f) evidence**: running tf-eu-guard on every pull request and in CI
produces a repeatable, timestamped assessment of the effectiveness of the controls
above. This mirrors GDPR Art. 32(1)(d) ("regularly testing, assessing and
evaluating"). See `.github/workflows/ci.yml`.

**Limitations**: Automated config assessment is one input to (f); it does not replace
periodic audits, penetration tests, or management review.

---

### NIS2 Article 21(2)(h) — Policies and procedures on the use of cryptography and encryption

**Legal requirement** (paraphrased):
> Policies and procedures regarding the use of cryptography and, where appropriate,
> encryption.

**Infrastructure controls** — encryption at rest for data stores:

| Check | Control |
|-------|---------|
| CKV_AWS_16 | RDS storage encrypted at rest |
| CKV_AWS_145 | S3 buckets encrypted with KMS by default |

**Evidence**: KMS-backed encryption gives auditable key management and rotation; a
green result shows data at rest is encrypted with managed keys.

**Limitations**: These checks cover encryption *at rest* for S3/RDS. Encryption *in
transit* (TLS enforcement), EBS volume encryption, and key-rotation policy are not
yet represented. (h) also expects a documented cryptography policy — an
organisational artefact.

---

### NIS2 Article 21(2)(i) — Human resources security, access control policies and asset management

**Legal requirement** (paraphrased):
> Human resources security, access control policies and asset management.

**Infrastructure controls** — this is the tool's strongest coverage area. Least
privilege, no standing over-permissive identities, and no public exposure of assets:

| Check | Control |
|-------|---------|
| CKV_AWS_62 | No `*:*` full-admin policies |
| CKV_AWS_274 | No use of AWS-managed AdministratorAccess |
| CKV_AWS_286 | No privilege-escalation actions |
| CKV_AWS_287 | No credential-exposure actions |
| CKV_AWS_288 | No data-exfiltration actions |
| CKV_AWS_273 | Access via SSO, not standing IAM users |
| CKV_AWS_40 | Policies attached to groups/roles, not users |
| CKV_AWS_9 | Password policy with rotation/strength |
| CKV_AWS_161 | RDS uses IAM authentication |
| CKV_AWS_17 | RDS not publicly accessible |
| CKV_AWS_20 | S3 not public-readable |
| CKV_AWS_130 | Subnets do not auto-assign public IPs |

**Evidence**: Each finding is a concrete, least-privilege or exposure violation with a
file/line reference — an auditable access-control inventory.

**Limitations**: Access control also depends on *who* the principals are and *how*
joiners/movers/leavers are managed (HR security), which the configuration cannot show.

---

### NIS2 Article 21(2)(j) — Multi-factor authentication and secured communications

**Legal requirement** (paraphrased):
> The use of multi-factor authentication or continuous authentication solutions, and
> secured voice, video and text communications, where appropriate.

**Infrastructure controls**: `CKV2_AWS_22` (IAM user has no console access, forcing
federated/programmatic access) is the closest IaC signal and is an expansion
candidate. True MFA enforcement lives in IAM Identity Center / account settings that
Terraform in this stack does not declare.

**Limitations**: MFA state is largely an account/identity-provider setting rather than
a per-resource attribute, so a resource-config linter has limited visibility into (j).

---

## Summary of registry coverage against NIS2 Art. 21(2)

| Point | Covered? | Checks |
|-------|----------|--------|
| (a) risk analysis | ✗ organisational | — |
| (b) incident handling | ✓ partial | 3 |
| (c) business continuity / backup | ✓ | 3 |
| (d) supply-chain security | ✗ organisational | — |
| (e) secure acquisition/dev/maintenance | ✓ (secrets) | EUGUARD_NIS2_001 (+CKV_AWS_226 candidate) |
| (f) assessing effectiveness | ✓ via CI usage | tool itself |
| (g) cyber hygiene / training | ✗ organisational | — |
| (h) cryptography / encryption | ✓ | 2 |
| (i) access control / asset mgmt | ✓ strong | 12 |
| (j) MFA / secured comms | ◐ candidate | (CKV2_AWS_22) |

✓ covered · ◐ partial/candidate · ✗ out of scope for a config linter
