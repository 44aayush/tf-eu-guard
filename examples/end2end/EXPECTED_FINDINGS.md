# Expected Findings — Predicted Enrichment

> **Note**: This is a **predicted** list of findings traced from the tf-eu-guard registry against the 14 terragoat files in this directory. It is NOT the output of an actual scan. Line numbers and resource identifiers are illustrative. To see real findings with precise line numbers, run:
> ```bash
> tf-eu-guard scan examples/end2end --output all
> ```

The registry (as of Phase 4 completion, 2026-08-26) contains 38 Checkov-to-EU-compliance mappings. Below are the checks expected to fire in this directory, grouped by compliance domain.

---

## IAM (Identity & Access Management)

### High Severity

**CKV_AWS_40** — IAM policies attached to users  
**Mapped to**: NIS2 Art. 21(2)(i) — Access control policies; GDPR Art. 32(1)(b) — Ability to ensure confidentiality  
**Expected instances**: `iam.tf` — `aws_iam_user_policy.userpolicy` grants `ec2:*`, `s3:*`, `lambda:*`, `cloudwatch:*` on `*`

**CKV_AWS_63** — IAM policy grants full administrative privileges  
**Mapped to**: NIS2 Art. 21(2)(i); GDPR Art. 32(1)(b)  
**Expected instances**: `iam.tf` — inline policy on user, `db-app.tf` — `aws_iam_role_policy.ec2policy` grants `s3:*`, `ec2:*`, `rds:*` on `*`

**CKV_AWS_62** — IAM policy attached directly to user  
**Mapped to**: NIS2 Art. 21(2)(i); GDPR Art. 32(1)(b)  
**Expected instances**: `iam.tf` — `aws_iam_user_policy.userpolicy`

### Additional IAM Checks (if mapped)

- **CKV_AWS_273** — IAM policy allows data exfiltration (S3/RDS over-permissions)
- **CKV_AWS_287** — IAM policy allows privilege escalation
- **CKV_AWS_288** — IAM policy allows credential exposure
- **CKV_AWS_286** — IAM user without MFA
- **CKV_AWS_355** — IAM role trust allows overly broad principals
- **CKV_AWS_289** — IAM policy with broad write/delete on critical resources
- **CKV_AWS_290** — IAM role without permission boundary
- **CKV_AWS_274** — IAM policy allows access from any IP
- **CKV_AWS_9** — Access logging not enabled on S3 (overlaps with S3 section)

---

## S3 (Storage)

### High Severity

**CKV_AWS_18** — S3 bucket without access logging  
**Mapped to**: NIS2 Art. 21(2)(f) — Security event logging; GDPR Art. 32(1)(d) — Procedures to test security effectiveness  
**Expected instances**: `s3.tf` — buckets `data`, `financials`, `operations`, `data_science` (4 instances)

**CKV_AWS_19** — S3 bucket without encryption  
**Mapped to**: NIS2 Art. 21(2)(h) — Encryption; GDPR Art. 32(1)(a) — Pseudonymization and encryption  
**Expected instances**: `s3.tf` — bucket `data` (1 instance)

**CKV_AWS_21** — S3 bucket without versioning  
**Mapped to**: NIS2 Art. 21(2)(c) — Backup and disaster recovery; GDPR Art. 32(1)(c) — Ability to restore availability  
**Expected instances**: `s3.tf` — buckets `data`, `financials`, `operations`, `data_science` (4 instances)

**CKV_AWS_145** — S3 bucket allows public read/write  
**Mapped to**: NIS2 Art. 21(2)(i); GDPR Art. 32(1)(b)  
**Expected instances**: `s3.tf` — bucket `data` has public ACL (1 instance)

**CKV_AWS_20** — S3 bucket without default encryption  
**Mapped to**: NIS2 Art. 21(2)(h); GDPR Art. 32(1)(a)  
**Expected instances**: `s3.tf` — bucket `data`

**CKV_AWS_53** — S3 bucket without lifecycle configuration (if mapped)  
**CKV2_AWS_6** — S3 bucket public access block not configured  
**Mapped to**: NIS2 Art. 21(2)(i); GDPR Art. 32(1)(b)  
**Expected instances**: `s3.tf` — all buckets

**CKV_AWS_54**, **CKV_AWS_55**, **CKV_AWS_56** — S3 public access block settings (individual flags)

---

## RDS (Databases)

### High/Critical Severity

**CKV_AWS_16** — RDS instance without encryption  
**Mapped to**: NIS2 Art. 21(2)(h); GDPR Art. 32(1)(a)  
**Expected instances**: `rds.tf` — 9 `aws_rds_cluster` resources (`app1` through `app9`); `db-app.tf` — `aws_db_instance.default` has `storage_encrypted = false`

**CKV_AWS_17** — RDS instance without backup retention  
**Mapped to**: NIS2 Art. 21(2)(c); GDPR Art. 32(1)(c)  
**Expected instances**: `rds.tf` — clusters with `backup_retention_period = 0` or `1`; `db-app.tf` — `backup_retention_period = 0`

**CKV_AWS_129** — RDS cluster without deletion protection  
**Mapped to**: NIS2 Art. 21(2)(c); GDPR Art. 32(1)(c)  
**Expected instances**: `rds.tf` — all 9 clusters lack `deletion_protection = true`

**CKV_AWS_133** — RDS cluster without IAM authentication  
**Mapped to**: NIS2 Art. 21(2)(i); GDPR Art. 32(1)(b)  
**Expected instances**: `rds.tf` — all 9 clusters; `neptune.tf` — `iam_database_authentication_enabled = false`

**CKV_AWS_161** — RDS instance publicly accessible  
**Mapped to**: NIS2 Art. 21(2)(i); GDPR Art. 32(1)(b)  
**Expected instances**: `db-app.tf` — `publicly_accessible = true`

**CKV_AWS_293** — RDS instance without enhanced monitoring  
**Mapped to**: NIS2 Art. 21(2)(f); GDPR Art. 32(1)(d)  
**Expected instances**: `db-app.tf` — `monitoring_interval = 0`

**CKV_AWS_118** — RDS instance without multi-AZ  
**Mapped to**: NIS2 Art. 21(2)(c); GDPR Art. 32(1)(c)  
**Expected instances**: `db-app.tf` — `multi_az = false`

**CKV_AWS_157** — Neptune cluster without encryption  
**Mapped to**: NIS2 Art. 21(2)(h); GDPR Art. 32(1)(a)  
**Expected instances**: `neptune.tf` — `storage_encrypted = false`

---

## Network & Infrastructure

### Medium/High Severity

**CKV2_AWS_11** — VPC flow logging not enabled  
**Mapped to**: NIS2 Art. 21(2)(f); GDPR Art. 32(1)(d)  
**Expected instances**: `ec2.tf` — VPC `web_vpc` has flow log to S3, but `eks.tf` — VPC `eks_vpc` and `db-app.tf` — usage of `web_vpc` without additional flow logs may trigger depending on check scope

**CKV_AWS_24**, **CKV_AWS_25** — Security group allows ingress from 0.0.0.0/0 on SSH (22) or other ports  
**Mapped to**: NIS2 Art. 21(2)(i); GDPR Art. 32(1)(b)  
**Expected instances**: `ec2.tf` — `aws_security_group.web-node` allows SSH + HTTP from `0.0.0.0/0`

**CKV_AWS_260** — Security group allows unrestricted egress  
**Mapped to**: NIS2 Art. 21(2)(i); GDPR Art. 32(1)(b)  
**Expected instances**: `ec2.tf`, `db-app.tf` — security groups with egress rule `0.0.0.0/0` on all ports

**CKV_AWS_382** — ELB (Classic Load Balancer) not using HTTPS  
**Mapped to**: NIS2 Art. 21(2)(h); GDPR Art. 32(1)(a)  
**Expected instances**: `elb.tf` — `aws_elb.weblb` has listener protocol `http` only

**CKV2_AWS_12** — ELB without deletion protection (if applicable)

**CKV_AWS_130** — VPC subnet auto-assigns public IPs  
**Mapped to**: NIS2 Art. 21(2)(i); GDPR Art. 32(1)(b)  
**Expected instances**: `ec2.tf` — `aws_subnet.web_subnet` and `web_subnet2` have `map_public_ip_on_launch = true`; `eks.tf` — `eks_subnet1` and `eks_subnet2` same; `db-app.tf` references these subnets

---

## Custom Checks

### Critical Severity

**EUGUARD_NIS2_001** — Hardcoded secrets detected  
**Mapped to**: NIS2 Art. 21(2)(e) — Secure handling of credentials; GDPR Art. 32(1)(b) — Confidentiality  
**Expected instances**:
- `providers.tf` — `provider "aws"` alias `plain_text_access_keys_provider` has literal `access_key` and `secret_key`
- `ec2.tf` — `user_data` contains `export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE` and `export AWS_SECRET_ACCESS_KEY=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`
- `lambda.tf` — `environment.variables` contains plaintext `access_key` and `secret_key`
- `db-app.tf` — `user_data` contains `DB_PASSWORD=${var.password}` (password interpolation into script)

### High Severity

**EUGUARD_GDPR_001** — Non-EU AWS region detected  
**Mapped to**: GDPR Art. 44 — Transfers of personal data to third countries  
**Expected instances**: `consts.tf` / `providers.tf` — `region = us-west-2` (non-EU region)

---

## Summary

**Predicted total mapped findings**: 35–45 (depending on whether all registry checks are active and how Checkov scopes multi-resource patterns).

The actual scan will produce:
1. **`--output dev`**: Terminal rich-table grouped by severity
2. **`--output json`**: Machine-readable findings array
3. **`--output security`**: HTML dashboard with severity breakdown
4. **`--output auditor`**: HTML article-by-article view (NIS2 21(2) and GDPR 32/44 sections)
5. **`--output all`**: Writes all three HTML reports

Run the scan to generate real findings with precise line numbers, resource names, and remediation guidance.
