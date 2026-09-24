# Expected Findings — Predicted Enrichment

> **Note**: This is a **predicted** list of findings traced from the tf-eu-guard registry against the Terraform files in this directory. It is NOT the output of an actual scan. Line numbers and resource identifiers are illustrative. To see real findings with precise line numbers, run:
> ```bash
> tf-eu-guard scan examples/end2end --output all
> ```

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

## Additional Service Coverage

The files below exercise registry coverage beyond the core resource set. Every
check that fires on them is mapped — a scan of this directory produces **zero
unmapped findings from these files**.

### DynamoDB

**CKV_AWS_119** — DynamoDB table not encrypted with a customer-managed KMS key
**Mapped to**: NIS2 Art. 21(2)(h) — Policies and procedures on the use of cryptography and encryption; GDPR Art. 32(1)(a) — Pseudonymisation and encryption of personal data
**Severity**: HIGH
**Expected instances**: `aws_dynamodb_table.sessions`

**CKV_AWS_28** — DynamoDB point-in-time recovery (backup) not enabled
**Mapped to**: NIS2 Art. 21(2)(c) — Business continuity, backup management and disaster recovery; GDPR Art. 32(1)(c) — Ability to restore availability and access to personal data in a timely manner
**Expected instances**: `aws_dynamodb_table.sessions`

### CloudFront (CDN)

**CKV_AWS_34** — CloudFront distribution ViewerProtocolPolicy is not set to HTTPS
**Mapped to**: NIS2 Art. 21(2)(h); GDPR Art. 32(1)(a)
**Severity**: CRITICAL
**Expected instances**: `aws_cloudfront_distribution.assets`

**CKV_AWS_174** — CloudFront viewer certificate is not using TLS v1.2 or higher
**Mapped to**: NIS2 Art. 21(2)(h); GDPR Art. 32(1)(a)
**Severity**: HIGH
**Expected instances**: `aws_cloudfront_distribution.assets`

**CKV2_AWS_42** — CloudFront distribution does not use a custom SSL certificate *(graph check)*
**Mapped to**: NIS2 Art. 21(2)(h); GDPR Art. 32(1)(a)
**Severity**: MEDIUM
**Expected instances**: `aws_cloudfront_distribution.assets`

**CKV_AWS_68** — CloudFront distribution does not have WAF enabled
**Mapped to**: NIS2 Art. 21(2)(b) — Incident handling; GDPR Art. 32(1)(b) — Confidentiality, integrity, availability and resilience of processing systems
**Severity**: MEDIUM
**Expected instances**: `aws_cloudfront_distribution.assets`

**CKV2_AWS_47** — CloudFront WAFv2 WebACL is not configured with AMR for the Log4j vulnerability *(graph check)*
**Mapped to**: NIS2 Art. 21(2)(b); GDPR Art. 32(1)(b)
**Severity**: MEDIUM
**Expected instances**: `aws_cloudfront_distribution.assets`

**CKV_AWS_86** — CloudFront distribution does not have access logging enabled
**Mapped to**: NIS2 Art. 21(2)(b); GDPR Art. 32(1)(b)
**Severity**: MEDIUM
**Expected instances**: `aws_cloudfront_distribution.assets`

**CKV_AWS_310** — CloudFront distribution does not have origin failover configured
**Mapped to**: NIS2 Art. 21(2)(c); GDPR Art. 32(1)(c)
**Severity**: MEDIUM
**Expected instances**: `aws_cloudfront_distribution.assets`

**CKV2_AWS_32** — CloudFront distribution has no response headers policy attached *(graph check)*
**Mapped to**: NIS2 Art. 21(2)(e) — Security in network and information systems acquisition, development and maintenance; GDPR Art. 32(1)(b)
**Severity**: LOW
**Expected instances**: `aws_cloudfront_distribution.assets`

**CKV_AWS_374** — CloudFront web distribution does not have geo restriction enabled
**Mapped to**: NIS2 Art. 21(2)(i) — Human resources security, access control policies and asset management; GDPR Art. 32(1)(b)
**Severity**: LOW
**Expected instances**: `aws_cloudfront_distribution.assets`

**CKV_AWS_305** — CloudFront distribution has no default root object configured
**Mapped to**: NIS2 Art. 21(2)(e)
**Severity**: LOW
**Expected instances**: `aws_cloudfront_distribution.assets`

### API Gateway (REST)

**CKV_AWS_276** — Data trace is enabled in API Gateway method settings
**Mapped to**: NIS2 Art. 21(2)(b); GDPR Art. 32(1)(b)
**Severity**: HIGH
**Expected instances**: `aws_api_gateway_method_settings.prod`
**Note**: This is *not* a logging gap — logging is on. Data trace logs full
request/response bodies, which is the exposure.

**CKV_AWS_76** — API Gateway stage does not have access logging enabled
**Mapped to**: NIS2 Art. 21(2)(b); GDPR Art. 32(1)(b)
**Severity**: MEDIUM
**Expected instances**: `aws_api_gateway_stage.prod`

**CKV2_AWS_51** — API Gateway endpoints do not use client certificate authentication *(graph check)*
**Mapped to**: NIS2 Art. 21(2)(j) — Authentication and secured communications; GDPR Art. 32(1)(b)
**Severity**: MEDIUM
**Expected instances**: `aws_api_gateway_stage.prod`

**CKV2_AWS_29** — Public API Gateway is not protected by WAF *(graph check)*
**Mapped to**: NIS2 Art. 21(2)(b); GDPR Art. 32(1)(b)
**Severity**: MEDIUM
**Expected instances**: `aws_api_gateway_stage.prod`

**CKV_AWS_237** — Create-before-destroy is not set for the API Gateway REST API
**Mapped to**: NIS2 Art. 21(2)(c); GDPR Art. 32(1)(c)
**Severity**: MEDIUM
**Expected instances**: `aws_api_gateway_rest_api.app`

**CKV_AWS_217** — Create-before-destroy is not set for the API Gateway deployment
**Mapped to**: NIS2 Art. 21(2)(c); GDPR Art. 32(1)(c)
**Severity**: MEDIUM
**Expected instances**: `aws_api_gateway_deployment.app`

**CKV_AWS_73** — API Gateway does not have X-Ray tracing enabled
**Mapped to**: NIS2 Art. 21(2)(b)
**Severity**: LOW
**Expected instances**: `aws_api_gateway_stage.prod`

**CKV_AWS_120** — API Gateway caching is not enabled
**Mapped to**: NIS2 Art. 21(2)(c); GDPR Art. 32(1)(b)
**Severity**: LOW
**Expected instances**: `aws_api_gateway_stage.prod`

**CKV_AWS_225** — API Gateway method setting caching is not enabled
**Mapped to**: NIS2 Art. 21(2)(c); GDPR Art. 32(1)(b)
**Severity**: LOW
**Expected instances**: `aws_api_gateway_method_settings.prod`

### SNS

**CKV_AWS_26** — SNS topic is not encrypted
**Mapped to**: NIS2 Art. 21(2)(h); GDPR Art. 32(1)(a)
**Severity**: HIGH
**Expected instances**: `aws_sns_topic.app_notifications`

### Secrets Manager

**CKV_AWS_149** — Secrets Manager secret is not encrypted using a KMS CMK
**Mapped to**: NIS2 Art. 21(2)(h); GDPR Art. 32(1)(a)
**Severity**: HIGH
**Expected instances**: `aws_secretsmanager_secret.db_password`
**Note**: Cross-references `EUGUARD_NIS2_001` — the value is already stored as a
literal in `db-app.tf`, so this gap compounds the hardcoded-secret finding.

**CKV2_AWS_57** — Secrets Manager secret does not have automatic rotation enabled *(graph check)*
**Mapped to**: NIS2 Art. 21(2)(e); GDPR Art. 32(1)(b)
**Severity**: MEDIUM
**Expected instances**: `aws_secretsmanager_secret.db_password`

### Application Load Balancer (ELBv2)

**CKV_AWS_2** — ALB listener protocol is HTTP, not HTTPS
**Mapped to**: NIS2 Art. 21(2)(h); GDPR Art. 32(1)(a)
**Severity**: CRITICAL
**Expected instances**: `aws_lb_listener.web_http`

**CKV_AWS_103** — Load balancer is not using at least TLS 1.2 *(graph check)*
**Mapped to**: NIS2 Art. 21(2)(h); GDPR Art. 32(1)(a)
**Severity**: HIGH
**Expected instances**: `aws_lb_listener.web_http`

**CKV_AWS_378** — Load balancer target group uses the HTTP protocol *(graph check)*
**Mapped to**: NIS2 Art. 21(2)(h); GDPR Art. 32(1)(a)
**Severity**: HIGH
**Expected instances**: `aws_lb_target_group.web`

**CKV2_AWS_20** — ALB does not redirect HTTP requests to HTTPS *(graph check)*
**Mapped to**: NIS2 Art. 21(2)(h); GDPR Art. 32(1)(a)
**Severity**: HIGH
**Expected instances**: `aws_lb.web`

**CKV2_AWS_28** — Public-facing ALB is not protected by WAF *(graph check)*
**Mapped to**: NIS2 Art. 21(2)(b); GDPR Art. 32(1)(b)
**Severity**: MEDIUM
**Expected instances**: `aws_lb.web`

**CKV_AWS_91** — ELBv2 does not have access logging enabled
**Mapped to**: NIS2 Art. 21(2)(b); GDPR Art. 32(1)(b)
**Severity**: MEDIUM
**Expected instances**: `aws_lb.web`

**CKV_AWS_131** — ALB does not drop HTTP headers
**Mapped to**: NIS2 Art. 21(2)(e); GDPR Art. 32(1)(b)
**Severity**: MEDIUM
**Expected instances**: `aws_lb.web`

**CKV_AWS_328** — ALB is not configured with defensive or strictest desync mitigation mode
**Mapped to**: NIS2 Art. 21(2)(e); GDPR Art. 32(1)(b)
**Severity**: MEDIUM
**Expected instances**: `aws_lb.web`

**CKV_AWS_150** — Load balancer does not have deletion protection enabled
**Mapped to**: NIS2 Art. 21(2)(c); GDPR Art. 32(1)(c)
**Severity**: MEDIUM
**Expected instances**: `aws_lb.web`

**CKV_AWS_261** — HTTP/HTTPS target group does not define a health check
**Mapped to**: NIS2 Art. 21(2)(c); GDPR Art. 32(1)(b)
**Severity**: LOW
**Expected instances**: `aws_lb_target_group.web`

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

**Predicted total mapped findings**: 100–120 across this directory — roughly 70–85 from the core resource set (IAM, S3, RDS, networking) and 34 from the additional service coverage (DynamoDB, CloudFront, API Gateway, SNS, Secrets Manager, and Application Load Balancer). Every check that fires on those services is mapped, so a scan of this directory produces **zero unmapped findings** (depending on whether all registry checks are active and how Checkov scopes multi-resource patterns).

The actual scan will produce:
1. **`--output dev`**: Terminal rich-table grouped by severity
2. **`--output json`**: Machine-readable findings array
3. **`--output security`**: HTML dashboard with severity breakdown
4. **`--output auditor`**: HTML article-by-article view (NIS2 21(2) and GDPR 32/44 sections)
5. **`--output all`**: Writes all three HTML reports

Run the scan to generate real findings with precise line numbers, resource names, and remediation guidance.
