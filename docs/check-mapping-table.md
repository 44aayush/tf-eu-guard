# Check Mapping Table: Checkov → NIS2 / GDPR

**Reference stack**: the vulnerable Terraform under [`examples/vulnerable-aws/`](../examples/vulnerable-aws/)
(`iam.tf`, `s3.tf`, `rds.tf`, `network.tf`, plus `outputs.tf`).
**Mapped in `registry-aws.yaml`**: **180 check IDs** — 178 stock Checkov policies plus
2 custom tf-eu-guard checks (**§**, added in Phase 3). The original 38-mapping core
covered the `vulnerable_tf/` reference stack; subsequent extensions (from
2026-08-30 on) grew the registry so that *every* Checkov check firing across the
in-repo stacks (`examples/vulnerable-aws/`, `examples/end2end/`) enriches.
Mapping counts in the docs are verified against the registries in CI
(`tools/check_doc_counts.py`), so they cannot drift.

Article letters are verified against **Directive (EU) 2022/2555 (NIS2) Art. 21(2)**
and **Regulation (EU) 2016/679 (GDPR) Art. 32(1)**. Full legal text and reasoning
live in [`nis2-mapping.md`](nis2-mapping.md) and [`gdpr-mapping.md`](gdpr-mapping.md).

> **Provenance / verification status.** The mappings were originally assembled from
> a captured Checkov 3.3.13 scan (`tests/fixtures/checkov-raw-output.json`) plus the
> Checkov policy index, at a time when Checkov could not be executed in the
> development environment. Checkov now runs in CI and locally, so every ID has been
> re-verified against live scans of both in-repo stacks: `examples/vulnerable-aws/`
> (50 failing checks, all mapped) and `examples/end2end/` (295 failing checks, all
> mapped — zero unmapped). The registry is kept in sync with the fixture stacks, and
> `tools/check_doc_counts.py` verifies the documented counts against the registries
> on every commit.

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

**Symbols**: **‡** mapped but does not fire on the current stacks (no triggering
resource yet). **§** custom tf-eu-guard check (not a stock Checkov policy; loaded via `--external-checks-dir`).

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
| CKV_AWS_24 | network.tf | aws_security_group | SSH (22) open to 0.0.0.0/0 | 21(2)(i) | 32(1)(b) | HIGH |
| CKV_AWS_25 ‡ | network.tf | aws_security_group | RDP (3389) open to 0.0.0.0/0 | 21(2)(i) | 32(1)(b) | HIGH |
| CKV_AWS_260 | network.tf | aws_security_group | HTTP (80) open to 0.0.0.0/0 | 21(2)(i) | – | MEDIUM |
| CKV_AWS_382 | network.tf | aws_security_group | Egress open to 0.0.0.0/0 | 21(2)(i) | – | MEDIUM |
| CKV2_AWS_12 | network.tf | aws_vpc | Default SG not restricted | 21(2)(i) | – | MEDIUM |
| CKV2_AWS_11 | network.tf | aws_vpc | VPC flow logging disabled | 21(2)(b) | – | MEDIUM |
| CKV_AWS_130 ‡ | network.tf | aws_subnet | Auto-assigns public IP | 21(2)(i) | 32(1)(b) | MEDIUM |
| EUGUARD_GDPR_001 § | main.tf | aws provider | Provider region outside the EU Sovereign Cloud | – | 44 | HIGH |
| EUGUARD_NIS2_001 § | rds.tf | aws_db_instance | Hardcoded DB password (literal) | 21(2)(e) | 32(1)(b) | CRITICAL |

### Coverage summary

- **By severity** (original 38): 9 CRITICAL · 15 HIGH · 14 MEDIUM — plus the
  extension above (180 total: 23 CRITICAL · 66 HIGH · 66 MEDIUM · 25 LOW).
- **By framework** (original 38): 21 map to **both** NIS2 and GDPR, 11 NIS2-only, 6 GDPR-only.
- **By file**: iam.tf (12), s3.tf (9), rds.tf (9), network.tf (7), main.tf (1).
- **By theme**: access control / least privilege (20), public exposure (7),
  encryption at rest (2), logging & detection (4), backup / resilience (4),
  authentication (1), data residency / international transfers (1), secrets in
  code (1). *(Some checks count in more than one theme.)*

---

## Verification status (live scans)

The mappings were originally authored from a captured scan plus the Checkov policy
index because Checkov could not run in the development environment at the time.
That is no longer the case: Checkov 3.3.13 now executes in CI and locally, and every
ID above has been re-verified against live scans of both in-repo stacks:

```bash
checkov -d examples/vulnerable-aws --output json --framework terraform --quiet --compact
checkov -d examples/end2end       --output json --framework terraform --quiet --compact
```

Measured results:

| Stack | Failing checks | Mapped | Unmapped |
|-------|---------------:|-------:|---------:|
| `examples/vulnerable-aws/` | 50 | 50 | **0** |
| `examples/end2end/` | 295 | 295 | **0** |

Every check that fires on either stack enriches, so a scan of either produces
**zero unmapped findings**. The `‡` markers in the table above are the only
dormant mappings — they are forward-looking and cost nothing at runtime:

- `CKV_AWS_274` — needs an `aws_iam_policy_attachment` using `AdministratorAccess`.
- `CKV_AWS_9` — needs an `aws_iam_account_password_policy` resource to evaluate.
- `CKV_AWS_25` — needs a security group with ingress on port 3389 (RDP).

`tools/check_doc_counts.py` verifies the documented counts against the registries
in CI, and `tools/smoke_check.py` re-scans the fixture stacks on every commit, so
the table cannot silently drift from what a real scan produces.

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

Severity distribution after the extension: **23 CRITICAL · 66 HIGH · 66 MEDIUM ·
25 LOW** (180 total; article refs: NIS2 129, GDPR 96).

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

1. **Scan-backed.** Every non-‡ ID above has been observed failing in a live
   Checkov 3.3.13 scan of the in-repo stacks (`examples/vulnerable-aws/`,
   `examples/end2end/`); the remaining ‡ IDs are authored from the Checkov policy
   index and are dormant only because no fixture yet holds a triggering resource.
   The registry stays honest about what has actually been reproduced.
2. **Severity is authored here.** Checkov 3.3.13 returns `severity: null`, so the
   registry is the source of truth for severity (see `docs/checkov-schema.md`).
3. **Conservative dual-mapping.** A check maps to *both* frameworks only where both
   articles genuinely apply (e.g. encryption → GDPR 32(1)(a) *and* NIS2 21(2)(h)).
   Logging/detection maps to NIS2 21(2)(b) only, not stretched to GDPR.
4. **No overclaiming.** These checks assess *infrastructure configuration*. Full
   NIS2/GDPR compliance also requires documented processes, DPIAs, and organisational
   measures a linter cannot verify.
