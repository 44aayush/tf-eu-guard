# Check Mapping Table: Checkov → NIS2 / GDPR

**Reference stack**: the vulnerable Terraform under [`examples/vulnerable-aws/`](../examples/vulnerable-aws/)
(`iam.tf`, `s3.tf`, `rds.tf`, `network.tf`, plus `outputs.tf`).
**Mapped in `registry-aws.yaml`**: **116 check IDs** — 114 stock Checkov policies plus
2 custom tf-eu-guard checks (**§**, added in Phase 3). The original 38-mapping core
covered the `vulnerable_tf/` reference stack; subsequent extensions (from
2026-08-30 on) grew the registry so that *every* Checkov check firing across the
in-repo stacks (`examples/vulnerable-aws/`, `examples/end2end/`) enriches.
Mapping counts in the docs are verified against the registries in CI
(`tools/check_doc_counts.py`), so they cannot drift.

Article letters are verified against **Directive (EU) 2022/2555 (NIS2) Art. 21(2)**
and **Regulation (EU) 2016/679 (GDPR) Art. 32(1)**. Full legal text and reasoning
live in [`nis2-mapping.md`](nis2-mapping.md) and [`gdpr-mapping.md`](gdpr-mapping.md).

> **Provenance / verification status.** The IAM, S3 and RDS check IDs — and the
> network checks `CKV2_AWS_11`, `CKV2_AWS_12`, `CKV_AWS_382`, `CKV_AWS_130` — were
> observed failing in a real Checkov 3.3.13 scan (`checkov-raw-output.json`), though
> that scan ran against an **earlier fixture set** at `…/tf-eu-guard/tf/`. The three
> open-ingress security-group checks marked **†** (`CKV_AWS_24`, `CKV_AWS_25`,
> `CKV_AWS_260`) are authored from the Checkov policy index: the earlier stack had no
> internet-facing ingress rules, so they were never observed. **Re-scan
> `examples/vulnerable-aws/` to confirm every ID** (command in "Verification status" below).

---

## Legend

**NIS2 Art. 21(2)** — cybersecurity risk-management measures:

| Letter | Measure (short) |
|--------|-----------------|
| (b) | Incident handling → detection, logging |
| (c) | Business continuity, backup management and disaster recovery |
| (e) | Security in network & information systems acquisition, development and maintenance |
| (h) | Policies and procedures on the use of cryptography and encryption |
| (i) | Human resources security, **access control** policies and asset management |
| (j) | Multi-factor authentication and secured communications |

**GDPR Art. 32(1)** — security of processing:

| Letter | Measure (short) |
|--------|-----------------|
| (a) | Pseudonymisation and **encryption** of personal data |
| (b) | Confidentiality, integrity, availability and resilience of processing systems |
| (c) | Ability to **restore** availability and access in a timely manner |

> One custom check cites **GDPR Art. 44** (Chapter V — *transfers of personal data to
> third countries*), which sits outside Art. 32(1): EU data residency is a lawful-transfer
> question, not a "security of processing" control.

**Symbols**: **†** ID authored from the policy index — confirm against an `examples/vulnerable-aws/`
scan. **‡** mapped but does not fire on the current stack (no triggering resource yet).
**§** custom tf-eu-guard check (not a stock Checkov policy; loaded via `--external-checks-dir`).

---

## Mapping Matrix (the original 38-check core)

| Check ID | File | Resource | Issue | NIS2 | GDPR | Severity |
|----------|------|----------|-------|------|------|----------|
| CKV_AWS_287 | iam.tf | iam user policy | Allows credentials exposure | 21(2)(i) | 32(1)(b) | CRITICAL |
| CKV_AWS_288 | iam.tf | iam user policy | Allows data exfiltration | 21(2)(i) | 32(1)(b) | CRITICAL |
| CKV_AWS_286 | iam.tf | iam user policy | Allows privilege escalation | 21(2)(i) | 32(1)(b) | CRITICAL |
| CKV_AWS_62 | iam.tf | iam user policy | Full `*:*` admin privileges | 21(2)(i) | 32(1)(b) | CRITICAL |
| CKV_AWS_63 | iam.tf | iam user policy | Wildcard `*` action | 21(2)(i) | 32(1)(b) | CRITICAL |
| CKV_AWS_289 | iam.tf | iam user policy | Permissions mgmt unconstrained | 21(2)(i) | 32(1)(b) | CRITICAL |
| CKV_AWS_273 | iam.tf | aws_iam_user | IAM users instead of SSO | 21(2)(i) | – | HIGH |
| CKV_AWS_355 | iam.tf | iam user policy | Wildcard `*` resource | 21(2)(i) | 32(1)(b) | HIGH |
| CKV_AWS_290 | iam.tf | iam user policy | Write access unconstrained | 21(2)(i) | 32(1)(b) | HIGH |
| CKV_AWS_274 ‡ | iam.tf | policy attachment | Uses AdministratorAccess policy | 21(2)(i) | – | HIGH |
| CKV_AWS_40 | iam.tf | iam user policy | Policy on user not group/role | 21(2)(i) | – | MEDIUM |
| CKV_AWS_9 ‡ | iam.tf | password policy | No password expiry (≤90d) | 21(2)(i) | – | MEDIUM |
| CKV_AWS_20 | s3.tf | aws_s3_bucket_acl | Public-READ ACL | 21(2)(i) | 32(1)(b) | CRITICAL |
| CKV_AWS_145 | s3.tf | aws_s3_bucket | Not encrypted with KMS | 21(2)(h) | 32(1)(a) | HIGH |
| CKV_AWS_53 | s3.tf | public access block | `block_public_acls` off | – | 32(1)(b) | HIGH |
| CKV_AWS_54 | s3.tf | public access block | `block_public_policy` off | – | 32(1)(b) | HIGH |
| CKV_AWS_55 | s3.tf | public access block | `ignore_public_acls` off | – | 32(1)(b) | HIGH |
| CKV_AWS_56 | s3.tf | public access block | `restrict_public_buckets` off | – | 32(1)(b) | HIGH |
| CKV2_AWS_6 | s3.tf | aws_s3_bucket | No public access block (logs/backup) | – | 32(1)(b) | HIGH |
| CKV_AWS_18 | s3.tf | aws_s3_bucket | No access logging | 21(2)(b) | – | MEDIUM |
| CKV_AWS_21 | s3.tf | aws_s3_bucket | Versioning disabled | 21(2)(c) | 32(1)(c) | MEDIUM |
| CKV_AWS_17 | rds.tf | aws_db_instance | Publicly accessible | 21(2)(i) | 32(1)(b) | CRITICAL |
| CKV_AWS_16 | rds.tf | aws_db_instance | Not encrypted at rest | 21(2)(h) | 32(1)(a) | HIGH |
| CKV_AWS_133 | rds.tf | aws_db_instance | No backup policy | 21(2)(c) | 32(1)(c) | HIGH |
| CKV_AWS_129 | rds.tf | aws_db_instance | Engine logs not exported | 21(2)(b) | – | MEDIUM |
| CKV_AWS_161 | rds.tf | aws_db_instance | IAM auth disabled | 21(2)(i) | 32(1)(b) | MEDIUM |
| CKV_AWS_293 | rds.tf | aws_db_instance | Deletion protection off | 21(2)(c) | 32(1)(c) | MEDIUM |
| CKV_AWS_118 | rds.tf | aws_db_instance | Enhanced monitoring off | 21(2)(b) | – | MEDIUM |
| CKV_AWS_157 | rds.tf | aws_db_instance | Multi-AZ disabled | 21(2)(c) | 32(1)(c) | MEDIUM |
| CKV_AWS_24 † | network.tf | aws_security_group | SSH (22) open to 0.0.0.0/0 | 21(2)(i) | 32(1)(b) | HIGH |
| CKV_AWS_25 † | network.tf | aws_security_group | RDP (3389) open to 0.0.0.0/0 | 21(2)(i) | 32(1)(b) | HIGH |
| CKV_AWS_260 † | network.tf | aws_security_group | HTTP (80) open to 0.0.0.0/0 | 21(2)(i) | – | MEDIUM |
| CKV_AWS_382 | network.tf | aws_security_group | Egress open to 0.0.0.0/0 | 21(2)(i) | – | MEDIUM |
| CKV2_AWS_12 | network.tf | aws_vpc | Default SG not restricted | 21(2)(i) | – | MEDIUM |
| CKV2_AWS_11 | network.tf | aws_vpc | VPC flow logging disabled | 21(2)(b) | – | MEDIUM |
| CKV_AWS_130 ‡ | network.tf | aws_subnet | Auto-assigns public IP | 21(2)(i) | 32(1)(b) | MEDIUM |
| EUGUARD_GDPR_001 § | main.tf | aws provider | Provider region outside the EU Sovereign Cloud | – | 44 | HIGH |
| EUGUARD_NIS2_001 § | rds.tf | aws_db_instance | Hardcoded DB password (literal) | 21(2)(e) | 32(1)(b) | CRITICAL |

### Coverage summary

- **By severity** (original 38): 9 CRITICAL · 15 HIGH · 14 MEDIUM — plus the
  extension above (116 total: 19 CRITICAL · 46 HIGH · 34 MEDIUM · 17 LOW).
- **By framework** (original 38): 21 map to **both** NIS2 and GDPR, 11 NIS2-only, 6 GDPR-only.
- **By file**: iam.tf (12), s3.tf (9), rds.tf (9), network.tf (7), main.tf (1).
- **By theme**: access control / least privilege (20), public exposure (7),
  encryption at rest (2), logging & detection (4), backup / resilience (4),
  authentication (1), data residency / international transfers (1), secrets in
  code (1). *(Some checks count in more than one theme.)*

---

## Verification status (`examples/vulnerable-aws/` re-scan)

The registry mappings above were assembled while Checkov could not be executed in
this environment (sandbox `seccomp` restriction). Before relying on the enriched
report, run one scan of the current stack and reconcile:

```bash
checkov -d examples/vulnerable-aws --output json --framework terraform --quiet --compact > tests/fixtures/checkov-vulnerable-tf.json
```

Then confirm three things:

1. **The † IDs exist and fire.** `CKV_AWS_24` (SSH), `CKV_AWS_25` (RDP) and
   `CKV_AWS_260` (HTTP) should appear against `aws_security_group.web_sg`,
   `admin_sg` and `db_sg`. If an ID differs in 3.3.13, rename the registry key —
   `enrich_findings()` simply drops a key that never matches, so a wrong guess is
   inert, not a false positive.
2. **The ‡ mappings are dormant on this stack** and will not appear in the report
   until the fixtures grow a triggering resource:
   - `CKV_AWS_274` — needs an `aws_iam_policy_attachment` using `AdministratorAccess`.
   - `CKV_AWS_9` — needs an `aws_iam_account_password_policy` resource to evaluate.
   - `CKV_AWS_130` — needs an `aws_subnet` with `map_public_ip_on_launch`.
   Either add those resources to the fixtures, or accept the mappings as
   forward-looking (they cost nothing at runtime).
3. **No mapped ID regressed.** Every non-‡ ID in the table should be present in the
   new scan output.

---

## Registry extension: beyond the original core

Every Checkov AWS check that fires against any in-repo stack is now mapped. The
extension is grouped by theme in `registry-aws.yaml` (check IDs below; full risk /
remediation text lives in the registry):

| Theme | NIS2 | GDPR | Checks |
|-------|------|------|--------|
| Encryption at rest | 21(2)(h) | 32(1)(a) | CKV2_AWS_2, CKV_AWS_3, 8, 96, 5, 247, 44, 347, 279, 280, 327, 136, 189, 186, 173, 58, 7, CKV2_AWS_64 |
| Encryption in transit | 21(2)(h) | 32(1)(a) | CKV_AWS_127, 376, 228, 379, CKV2_AWS_69 |
| Logging / detection | 21(2)(b) | 32(1)(b) | CKV_AWS_101, 84, 317, 324, 325, 92, 37, 50, 126, 353, CKV2_AWS_30, CKV2_AWS_62 |
| Backup / resilience / recovery | 21(2)(c) | 32(1)(b)/(c) | CKV_AWS_144, CKV2_AWS_8, CKV_AWS_326, 361, 139, CKV2_AWS_58, 115, 116, 135, CKV2_AWS_59, 318, CKV2_AWS_61, 313, 362, CKV2_AWS_60 |
| Secure development / supply chain | 21(2)(e) | 32(1)(b) | CKV_AWS_226, 363, 272, 51, 163 |
| Secrets in code | 21(2)(e) | 32(1)(b) | CKV_AWS_41, 45, 46 |
| IAM / access control | 21(2)(i) | 32(1)(b) | CKV2_AWS_40, CKV_AWS_109, 111, 283, 356, 70, CKV2_AWS_41, 79, 162, 359, CKV2_AWS_52 |
| Network segmentation | 21(2)(i) | 32(1)(b) | CKV_AWS_137, 248, 38, 39, 117, CKV2_AWS_5, 23 |

Severity distribution after the extension: **19 CRITICAL · 46 HIGH · 34 MEDIUM ·
17 LOW** (116 total; article refs: NIS2 110, GDPR 81).

### Checks still intentionally unmapped

Unmapped findings are excluded from the mapped-findings reports but are surfaced
as a count in every format — they no longer vanish silently (see the CLI's
unmapped-findings handling and `examples/unmapped-aws/`, a fixture that
deliberately fails the password-policy family). Remaining unmapped checks are
those with **no honest compliance link** (e.g. the password-policy family
`CKV_AWS_10`/`11`/`12`/`13`/`14`/`15`, already represented by the mapped
`CKV_AWS_9` account-level check) or that simply do not fire on any in-repo
stack. Mapping the *entire* Checkov AWS catalogue (~700 checks) was rejected
deliberately: entries exist to explain real findings, not to paint every
conceivable check with an article reference the code doesn't justify.

---

## Methodology notes

1. **Scan-backed where possible; flagged where not.** Every ID except the three **†**
   security-group checks was observed failing in `checkov-raw-output.json`. The **†**
   IDs are authored from the Checkov policy index and must be confirmed against a
   `examples/vulnerable-aws/` scan (see "Verification status"). This split is deliberate: the
   registry stays honest about what has actually been reproduced.
2. **Severity is authored here.** Checkov 3.3.13 returns `severity: null`, so the
   registry is the source of truth for severity (see `docs/checkov-schema.md`).
3. **Conservative dual-mapping.** A check maps to *both* frameworks only where both
   articles genuinely apply (e.g. encryption → GDPR 32(1)(a) *and* NIS2 21(2)(h)).
   Logging/detection maps to NIS2 21(2)(b) only, not stretched to GDPR.
4. **No overclaiming.** These checks assess *infrastructure configuration*. Full
   NIS2/GDPR compliance also requires documented processes, DPIAs, and organisational
   measures a linter cannot verify.
