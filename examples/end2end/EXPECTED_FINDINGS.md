# Expected Findings — Predicted Enrichment

> **Note**: This is a **predicted** list of findings traced from the tf-eu-guard registry against the Terraform files in this directory. It is NOT the output of an actual scan. Line numbers and resource identifiers are illustrative. To see real findings with precise line numbers, run:
> ```bash
> tf-eu-guard scan examples/end2end --output all
> ```

---

## IAM (Identity & Access Management)

### High Severity

**CKV_AWS_40** — IAM policies attached to users  
**Mapped to**: NIS2 Art. 21(2)(i) — Access control policies  
**Expected instances**: none in this suite (mapped, but no IAM policy is attached directly to a user)

### Critical Severity

**CKV_AWS_63** — Ensure no IAM policies documents allow "*" as a statement's actions  
**Mapped to**: NIS2 Art. 21(2)(i) — Human resources security, access control policies and asset management; GDPR Art. 32(1)(b) — Confidentiality, integrity, availability and resilience of processing systems  
**Severity**: CRITICAL  
**Expected instances**: `iam.tf` — `aws_iam_user_policy.userpolicy`; `db-app.tf` — `aws_iam_role_policy.ec2policy`

**CKV_AWS_62** — Ensure IAM policies that allow full "*-*" administrative privileges are not created  
**Mapped to**: NIS2 Art. 21(2)(i); GDPR Art. 32(1)(b)  
**Severity**: CRITICAL  
**Expected instances**: `iam.tf` — `aws_iam_user_policy.userpolicy`

**CKV_AWS_287** — Ensure IAM policies does not allow credentials exposure  
**Mapped to**: NIS2 Art. 21(2)(i); GDPR Art. 32(1)(b)  
**Severity**: CRITICAL  
**Expected instances**: `iam.tf` — `aws_iam_user_policy.userpolicy`; `db-app.tf` — `aws_iam_role_policy.ec2policy`

**CKV_AWS_288** — Ensure IAM policies does not allow data exfiltration  
**Mapped to**: NIS2 Art. 21(2)(i); GDPR Art. 32(1)(b)  
**Severity**: CRITICAL  
**Expected instances**: `iam.tf` — `aws_iam_user_policy.userpolicy`; `db-app.tf` — `aws_iam_role_policy.ec2policy`

**CKV_AWS_286** — Ensure IAM policies does not allow privilege escalation  
**Mapped to**: NIS2 Art. 21(2)(i); GDPR Art. 32(1)(b)  
**Severity**: CRITICAL  
**Expected instances**: `iam.tf` — `aws_iam_user_policy.userpolicy`

**CKV_AWS_289** — Ensure IAM policies does not allow permissions management / resource exposure without constraints  
**Mapped to**: NIS2 Art. 21(2)(i); GDPR Art. 32(1)(b)  
**Severity**: CRITICAL  
**Expected instances**: `iam.tf` — `aws_iam_user_policy.userpolicy`; `db-app.tf` — `aws_iam_role_policy.ec2policy`

### High Severity

**CKV_AWS_355** — Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions  
**Mapped to**: NIS2 Art. 21(2)(i); GDPR Art. 32(1)(b)  
**Severity**: HIGH  
**Expected instances**: `iam.tf` — `aws_iam_user_policy.userpolicy`; `db-app.tf` — `aws_iam_role_policy.ec2policy`

**CKV_AWS_290** — Ensure IAM policies does not allow write access without constraints  
**Mapped to**: NIS2 Art. 21(2)(i); GDPR Art. 32(1)(b)  
**Severity**: HIGH  
**Expected instances**: `iam.tf` — `aws_iam_user_policy.userpolicy`; `db-app.tf` — `aws_iam_role_policy.ec2policy`

**CKV_AWS_273** — Ensure access is controlled through SSO and not AWS IAM defined users  
**Mapped to**: NIS2 Art. 21(2)(i) — Human resources security, access control policies and asset management  
**Severity**: HIGH  
**Expected instances**: `iam.tf` — `aws_iam_user.user`

### Mapped but not triggered in this suite

- **CKV_AWS_40** (MEDIUM) — Ensure IAM policies are attached only to groups or roles. Mapped to NIS2 Art. 21(2)(i). No IAM policy is attached directly to a user here, so this check does not fire.
- **CKV_AWS_274** (HIGH) — Disallow IAM roles, users, and groups from using the AWS AdministratorAccess policy. Mapped to NIS2 Art. 21(2)(i). No principal attaches the managed `AdministratorAccess` policy, so this check does not fire.
- **CKV_AWS_9** (MEDIUM) — Ensure IAM password policy expires passwords within 90 days or less. Mapped to NIS2 Art. 21(2)(i). There is no `aws_iam_account_password_policy` resource in this suite, so this check does not fire.

---

## S3 (Storage)

### Critical Severity

**CKV_AWS_20** — S3 Bucket has an ACL defined which allows public READ access  
**Mapped to**: NIS2 Art. 21(2)(i) — Human resources security, access control policies and asset management; GDPR Art. 32(1)(b) — Confidentiality, integrity, availability and resilience of processing systems  
**Severity**: CRITICAL  
**Expected instances**: none in this suite (mapped, but no bucket carries a public-read ACL)

### High Severity

**CKV_AWS_145** — Ensure that S3 buckets are encrypted with KMS by default  
**Mapped to**: NIS2 Art. 21(2)(h) — Policies and procedures on the use of cryptography and encryption; GDPR Art. 32(1)(a) — Pseudonymisation and encryption of personal data  
**Severity**: HIGH  
**Expected instances**: `s3.tf` — `flowbucket`, `data`, `data_science`, `financials`, `operations`

**CKV2_AWS_6** — Ensure that S3 bucket has a Public Access block  
**Mapped to**: GDPR Art. 32(1)(b) — Confidentiality, integrity, availability and resilience of processing systems  
**Severity**: HIGH  
**Expected instances**: `s3.tf` — all six buckets (`flowbucket`, `data`, `data_science`, `financials`, `logs`, `operations`)

### Medium Severity

**CKV_AWS_18** — Ensure the S3 bucket has access logging enabled  
**Mapped to**: NIS2 Art. 21(2)(b) — Incident handling  
**Severity**: MEDIUM  
**Expected instances**: `s3.tf` — `flowbucket`, `data`, `financials`, `logs`, `operations`

**CKV_AWS_21** — Ensure all data stored in the S3 bucket have versioning enabled  
**Mapped to**: NIS2 Art. 21(2)(c) — Business continuity, backup management and disaster recovery; GDPR Art. 32(1)(c) — Ability to restore availability and access to personal data in a timely manner  
**Severity**: MEDIUM  
**Expected instances**: `s3.tf` — `flowbucket`, `data`, `financials`

### Mapped but not triggered in this suite

- **CKV_AWS_53** (HIGH) — Ensure S3 bucket has block public ACLs enabled. Mapped to GDPR Art. 32(1)(b). Every bucket sets `block_public_acls = true`, so this check does not fire.
- **CKV_AWS_54** (HIGH) — Ensure S3 bucket has block public policy enabled. Mapped to GDPR Art. 32(1)(b). Every bucket sets `block_public_policy = true`.
- **CKV_AWS_55** (HIGH) — Ensure S3 bucket has ignore public ACLs enabled. Mapped to GDPR Art. 32(1)(b). Every bucket sets `ignore_public_acls = true`.
- **CKV_AWS_56** (HIGH) — Ensure S3 bucket has 'restrict_public_buckets' enabled. Mapped to GDPR Art. 32(1)(b). Every bucket sets `restrict_public_buckets = true`.

---

## RDS (Databases)

### Critical Severity

**CKV_AWS_17** — Ensure all data stored in RDS is not publicly accessible  
**Mapped to**: NIS2 Art. 21(2)(i) — Human resources security, access control policies and asset management; GDPR Art. 32(1)(b) — Confidentiality, integrity, availability and resilience of processing systems  
**Severity**: CRITICAL  
**Expected instances**: `db-app.tf` — `aws_db_instance.default` (`publicly_accessible = true`)

### High Severity

**CKV_AWS_16** — Ensure all data stored in the RDS is securely encrypted at rest  
**Mapped to**: NIS2 Art. 21(2)(h) — Policies and procedures on the use of cryptography and encryption; GDPR Art. 32(1)(a) — Pseudonymisation and encryption of personal data  
**Severity**: HIGH  
**Expected instances**: `db-app.tf` — `aws_db_instance.default` (`storage_encrypted = false`)

**CKV_AWS_133** — Ensure that RDS instances has backup policy  
**Mapped to**: NIS2 Art. 21(2)(c) — Business continuity, backup management and disaster recovery; GDPR Art. 32(1)(c) — Ability to restore availability and access to personal data in a timely manner  
**Severity**: HIGH  
**Expected instances**: `db-app.tf` — `aws_db_instance.default`; `rds.tf` — `aws_rds_cluster.app1-rds-cluster`

### Medium Severity

**CKV_AWS_129** — Ensure that respective logs of Amazon Relational Database Service (Amazon RDS) are enabled  
**Mapped to**: NIS2 Art. 21(2)(b) — Incident handling  
**Severity**: MEDIUM  
**Expected instances**: `db-app.tf` — `aws_db_instance.default`

**CKV_AWS_161** — Ensure RDS database has IAM authentication enabled  
**Mapped to**: NIS2 Art. 21(2)(i) — Human resources security, access control policies and asset management; GDPR Art. 32(1)(b) — Confidentiality, integrity, availability and resilience of processing systems  
**Severity**: MEDIUM  
**Expected instances**: `db-app.tf` — `aws_db_instance.default`

**CKV_AWS_293** — Ensure that AWS database instances have deletion protection enabled  
**Mapped to**: NIS2 Art. 21(2)(c) — Business continuity, backup management and disaster recovery; GDPR Art. 32(1)(c) — Ability to restore availability and access to personal data in a timely manner  
**Severity**: MEDIUM  
**Expected instances**: `db-app.tf` — `aws_db_instance.default`

**CKV_AWS_118** — Ensure that enhanced monitoring is enabled for Amazon RDS instances  
**Mapped to**: NIS2 Art. 21(2)(b) — Incident handling  
**Severity**: MEDIUM  
**Expected instances**: `db-app.tf` — `aws_db_instance.default`

**CKV_AWS_157** — Ensure that RDS instances have Multi-AZ enabled  
**Mapped to**: NIS2 Art. 21(2)(c) — Business continuity, backup management and disaster recovery; GDPR Art. 32(1)(c) — Ability to restore availability and access to personal data in a timely manner  
**Severity**: MEDIUM  
**Expected instances**: `db-app.tf` — `aws_db_instance.default`

---

## Network & Infrastructure

### High Severity

**CKV_AWS_24** — Ensure no security groups allow ingress from 0.0.0.0:0 to port 22  
**Mapped to**: NIS2 Art. 21(2)(i) — Human resources security, access control policies and asset management; GDPR Art. 32(1)(b) — Confidentiality, integrity, availability and resilience of processing systems  
**Severity**: HIGH  
**Expected instances**: `ec2.tf` — `aws_security_group.web-node`

### Medium Severity

**CKV2_AWS_11** — Ensure VPC flow logging is enabled in all VPCs  
**Mapped to**: NIS2 Art. 21(2)(b) — Incident handling  
**Severity**: MEDIUM  
**Expected instances**: `eks.tf` — `aws_vpc.eks_vpc` (`web_vpc` in `ec2.tf` has a flow log)

**CKV_AWS_260** — Ensure no security groups allow ingress from 0.0.0.0:0 to port 80  
**Mapped to**: NIS2 Art. 21(2)(i) — Human resources security, access control policies and asset management  
**Severity**: MEDIUM  
**Expected instances**: `ec2.tf` — `aws_security_group.web-node`

**CKV_AWS_382** — Ensure no security groups allow egress from 0.0.0.0:0 to port -1  
**Mapped to**: NIS2 Art. 21(2)(i) — Human resources security, access control policies and asset management  
**Severity**: MEDIUM  
**Expected instances**: `db-app.tf` — `aws_security_group_rule.egress`; `ec2.tf` — `aws_security_group.web-node`

**CKV2_AWS_12** — Ensure the default security group of every VPC restricts all traffic  
**Mapped to**: NIS2 Art. 21(2)(i) — Human resources security, access control policies and asset management  
**Severity**: MEDIUM  
**Expected instances**: `ec2.tf` — `aws_default_security_group.web_vpc_default_sg`; `eks.tf` — `aws_default_security_group.eks_vpc_default_sg`

**CKV_AWS_130** — Ensure VPC subnets do not assign public IP by default  
**Mapped to**: NIS2 Art. 21(2)(i) — Human resources security, access control policies and asset management; GDPR Art. 32(1)(b) — Confidentiality, integrity, availability and resilience of processing systems  
**Severity**: MEDIUM  
**Expected instances**: `ec2.tf` — `aws_subnet.web_subnet`, `aws_subnet.web_subnet2`; `eks.tf` — `aws_subnet.eks_subnet1`, `aws_subnet.eks_subnet2`

### Mapped but not triggered in this suite

- **CKV_AWS_25** (HIGH) — Ensure no security groups allow ingress from 0.0.0.0:0 to port 3389. Mapped to NIS2 Art. 21(2)(i); GDPR Art. 32(1)(b). No security group opens port 3389 (RDP), so this check does not fire.

---

## Additional Service Coverage

The files below exercise registry coverage beyond the core resource set. Every check that fires across this directory is mapped, so a scan produces **zero unmapped findings** (measured: 295 mapped).

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

### CloudTrail

**CKV_AWS_67** — Ensure CloudTrail is enabled in all Regions
**Mapped to**: NIS2 Art. 21(2)(b) — Incident handling
**Severity**: HIGH
**Expected instances**: `cloudtrail.tf` — `aws_cloudtrail.account_trail` has `is_multi_region_trail = false`, so out-of-region activity leaves no audit trail (relevant under the EUSC-only `EUGUARD_GDPR_001` policy)

**CKV_AWS_35** — Ensure CloudTrail logs are encrypted at rest using KMS CMKs
**Mapped to**: NIS2 Art. 21(2)(h); GDPR Art. 32(1)(a)
**Severity**: HIGH
**Expected instances**: `cloudtrail.tf` — no `kms_key_id`, so log files are SSE-S3 rather than customer-key encrypted

**CKV_AWS_36** — Ensure CloudTrail log file validation is enabled
**Mapped to**: NIS2 Art. 21(2)(b); GDPR Art. 32(1)(b)
**Severity**: MEDIUM
**Expected instances**: `cloudtrail.tf` — `enable_log_file_validation = false`, so the audit trail's own integrity is not protected

**CKV_AWS_252** — Ensure CloudTrail defines an SNS Topic
**Mapped to**: NIS2 Art. 21(2)(b)
**Severity**: LOW
**Expected instances**: `cloudtrail.tf` — no `sns_topic_name`, so no notification on new log delivery

**CKV2_AWS_10** — Ensure CloudTrail trails are integrated with CloudWatch Logs *(graph check)*
**Mapped to**: NIS2 Art. 21(2)(b)
**Severity**: MEDIUM
**Expected instances**: `cloudtrail.tf` — no `cloud_watch_logs_role_arn` / `cloud_watch_logs_group_arn`

### CodeBuild

**CKV_AWS_316** — Ensure CodeBuild project environments do not have privileged mode enabled
**Mapped to**: NIS2 Art. 21(2)(e) — Security in network and information systems acquisition, development and maintenance; GDPR Art. 32(1)(b)
**Severity**: HIGH
**Expected instances**: `codebuild.tf` — `aws_codebuild_project.app` has `privileged_mode = true`

**CKV_AWS_147** — Ensure CodeBuild project artifacts are encrypted using a KMS CMK
**Mapped to**: NIS2 Art. 21(2)(h); GDPR Art. 32(1)(a)
**Severity**: HIGH
**Expected instances**: `codebuild.tf` — `artifacts` block has no `encryption_key`

**CKV_AWS_314** — Ensure CodeBuild project environments have a logging configuration
**Mapped to**: NIS2 Art. 21(2)(b)
**Severity**: MEDIUM
**Expected instances**: `codebuild.tf` — no `logs_config` block

### ECS

**CKV_AWS_333** — Ensure ECS task definitions do not have public IP assigned
**Mapped to**: NIS2 Art. 21(2)(i); GDPR Art. 32(1)(b)
**Severity**: CRITICAL
**Expected instances**: `ecs.tf` — `aws_ecs_service.app` sets `assign_public_ip = true`

**CKV_AWS_223** — Ensure ECS cluster enables ECS Exec logging
**Mapped to**: NIS2 Art. 21(2)(b)
**Severity**: HIGH
**Expected instances**: `ecs.tf` — `aws_ecs_cluster.batch` sets `logging = "NONE"`

**CKV_AWS_224** — Ensure ECS Exec uses KMS encryption with a customer-managed key
**Mapped to**: NIS2 Art. 21(2)(h)
**Severity**: MEDIUM
**Expected instances**: `ecs.tf` — `aws_ecs_cluster.app` sets `kms_key_id` but has no `log_configuration` with encryption enabled

**CKV_AWS_336** — Ensure ECS task definition has a read-only root file system
**Mapped to**: NIS2 Art. 21(2)(e); GDPR Art. 32(1)(b)
**Severity**: MEDIUM
**Expected instances**: `ecs.tf` — container definition has no `readonly_root_filesystem`

**CKV_AWS_332** — Ensure ECS Service uses the latest Fargate platform version
**Mapped to**: NIS2 Art. 21(2)(e)
**Severity**: MEDIUM
**Expected instances**: `ecs.tf` — `aws_ecs_service.app` pins `platform_version = "1.3.0"`

**CKV_AWS_249** — Ensure ECS task definition does not have the same task and execution role
**Mapped to**: NIS2 Art. 21(2)(i)
**Severity**: MEDIUM
**Expected instances**: `ecs.tf` — `aws_ecs_task_definition.app` sets `task_role_arn` and `execution_role_arn` to the same role

**CKV_AWS_65** — Ensure ECS cluster has container insights enabled
**Mapped to**: NIS2 Art. 21(2)(b)
**Severity**: MEDIUM
**Expected instances**: `ecs.tf` — `aws_ecs_cluster.app` and `aws_ecs_cluster.batch` have no `setting` block (2 instances)

### ElastiCache

**CKV_AWS_29** — Ensure all data stored in the ElastiCache Replication Group is securely encrypted at rest  
**Mapped to**: NIS2 Art. 21(2)(h); GDPR Art. 32(1)(a)  
**Severity**: HIGH  
**Expected instances**: `elasticache.tf` — `aws_elasticache_replication_group.sessions` has no `at_rest_encryption_enabled`

**CKV_AWS_30** — Ensure all data stored in the ElastiCache Replication Group is securely encrypted in transit  
**Mapped to**: NIS2 Art. 21(2)(h); GDPR Art. 32(1)(a)  
**Severity**: HIGH  
**Expected instances**: `elasticache.tf` — no `transit_encryption_enabled`

**CKV_AWS_31** — Ensure all data stored in the ElastiCache Replication Group is securely encrypted in transit and has an auth token  
**Mapped to**: NIS2 Art. 21(2)(i); GDPR Art. 32(1)(b)  
**Severity**: HIGH  
**Expected instances**: `elasticache.tf` — no `auth_token`, so any client that can reach the cluster can read and write its keys

**CKV_AWS_191** — Ensure ElastiCache replication group is encrypted by KMS using a customer-managed key (CMK)  
**Mapped to**: NIS2 Art. 21(2)(h); GDPR Art. 32(1)(a)  
**Severity**: MEDIUM  
**Expected instances**: `elasticache.tf` — no `kms_key_id`, so encryption (if enabled) would use an AWS owned key

**CKV2_AWS_50** — Ensure ElastiCache Redis cluster has Multi-AZ automatic failover enabled *(graph check)*  
**Mapped to**: NIS2 Art. 21(2)(c); GDPR Art. 32(1)(c)  
**Severity**: MEDIUM  
**Expected instances**: `elasticache.tf` — `automatic_failover_enabled = false`, so the loss of one node takes the whole session store down

### Aurora (RDS Cluster)

**CKV_AWS_96** — Ensure all data stored in the Aurora RDS cluster is securely encrypted at rest  
**Mapped to**: NIS2 Art. 21(2)(h); GDPR Art. 32(1)(a)  
**Severity**: CRITICAL  
**Expected instances**: `rds-cluster.tf` — `aws_rds_cluster.aurora` has no `storage_encrypted`

**CKV_AWS_327** — Ensure RDS cluster is encrypted by KMS using a customer-managed key (CMK)  
**Mapped to**: NIS2 Art. 21(2)(h); GDPR Art. 32(1)(a)  
**Severity**: MEDIUM  
**Expected instances**: `rds-cluster.tf` — no `kms_key_id`

**CKV_AWS_313** — Ensure RDS cluster copies tags to snapshots  
**Mapped to**: NIS2 Art. 21(2)(c); GDPR Art. 32(1)(c)  
**Severity**: MEDIUM  
**Expected instances**: `rds-cluster.tf` — no `copy_tags_to_snapshot`

**CKV_AWS_324** — Ensure RDS cluster has log exports enabled  
**Mapped to**: NIS2 Art. 21(2)(b)  
**Severity**: MEDIUM  
**Expected instances**: `rds-cluster.tf` — no `enabled_cloudwatch_logs_exports`

**CKV_AWS_325** — Ensure RDS cluster has deletion protection enabled  
**Mapped to**: NIS2 Art. 21(2)(c); GDPR Art. 32(1)(c)  
**Severity**: MEDIUM  
**Expected instances**: `rds-cluster.tf` — no `deletion_protection`

**CKV_AWS_326** — Ensure RDS cluster has backtracking enabled  
**Mapped to**: NIS2 Art. 21(2)(c); GDPR Art. 32(1)(c)  
**Severity**: MEDIUM  
**Expected instances**: `rds-cluster.tf` — no `backtrack_window`

**CKV_AWS_162** — Ensure RDS cluster has IAM database authentication enabled  
**Mapped to**: NIS2 Art. 21(2)(i); GDPR Art. 32(1)(b)  
**Severity**: MEDIUM  
**Expected instances**: `rds-cluster.tf` — no `iam_database_authentication_enabled`

**CKV_AWS_139** — Ensure RDS cluster has enhanced monitoring enabled  
**Mapped to**: NIS2 Art. 21(2)(b)  
**Severity**: MEDIUM  
**Expected instances**: `rds-cluster.tf` — no `enhanced_monitoring_resource_id` / monitoring role

**CKV2_AWS_8** — Ensure RDS cluster is covered by an AWS Backup plan *(graph check)*  
**Mapped to**: NIS2 Art. 21(2)(c); GDPR Art. 32(1)(c)  
**Severity**: MEDIUM  
**Expected instances**: `rds-cluster.tf` — no `aws_backup_selection` targeting the cluster

### Redshift

**CKV_AWS_87** — Redshift cluster should not be publicly accessible  
**Mapped to**: NIS2 Art. 21(2)(i); GDPR Art. 32(1)(b)  
**Severity**: CRITICAL  
**Expected instances**: `redshift.tf` — `aws_redshift_cluster.warehouse` sets `publicly_accessible = true`

**CKV_AWS_64** — Ensure all data stored in the Redshift cluster is securely encrypted at rest  
**Mapped to**: NIS2 Art. 21(2)(h); GDPR Art. 32(1)(a)  
**Severity**: HIGH  
**Expected instances**: `redshift.tf` — no `encrypted = true`

**CKV_AWS_142** — Ensure that Redshift cluster is encrypted by KMS using a customer-managed key  
**Mapped to**: NIS2 Art. 21(2)(h); GDPR Art. 32(1)(a)  
**Severity**: MEDIUM  
**Expected instances**: `redshift.tf` — no `kms_key_id`

**CKV_AWS_71** — Ensure Redshift cluster logging is enabled  
**Mapped to**: NIS2 Art. 21(2)(b)  
**Severity**: MEDIUM  
**Expected instances**: `redshift.tf` — no `logging` block, so there is no record of who queried the warehouse

**CKV_AWS_321** — Ensure Redshift clusters use enhanced VPC routing  
**Mapped to**: NIS2 Art. 21(2)(i)  
**Severity**: MEDIUM  
**Expected instances**: `redshift.tf` — no `enhanced_vpc_routing = true`, so COPY/UNLOAD traffic leaves the VPC

**CKV_AWS_391** — Avoid Redshift cluster with a commonly used master username and public access enabled  
**Mapped to**: NIS2 Art. 21(2)(i); GDPR Art. 32(1)(b)  
**Severity**: HIGH  
**Expected instances**: `redshift.tf` — `master_username = "admin"` on an internet-reachable cluster

**CKV_AWS_154** — Ensure Redshift is not deployed outside of a VPC *(graph check)*  
**Mapped to**: NIS2 Art. 21(2)(i); GDPR Art. 32(1)(b)  
**Severity**: HIGH  
**Expected instances**: `redshift.tf` — no `cluster_subnet_group_name`

### WAFv2

**CKV_AWS_192** — Ensure WAF prevents message lookup in Log4j2 (CVE-2021-44228)  
**Mapped to**: NIS2 Art. 21(2)(b); GDPR Art. 32(1)(b)  
**Severity**: MEDIUM  
**Expected instances**: `waf.tf` — `aws_wafv2_web_acl.app` omits the `AWSManagedRulesKnownBadInputsRuleSet` managed rule group

**CKV_AWS_175** — Ensure WAF has associated rules  
**Mapped to**: NIS2 Art. 21(2)(b); GDPR Art. 32(1)(b)  
**Severity**: MEDIUM  
**Expected instances**: `waf.tf` — the ACL carries no rules and defaults to allow, so it inspects no traffic

**CKV2_AWS_31** — Ensure WAFv2 has a logging configuration *(graph check)*  
**Mapped to**: NIS2 Art. 21(2)(b); GDPR Art. 32(1)(b)  
**Severity**: MEDIUM  
**Expected instances**: `waf.tf` — no `aws_wafv2_web_acl_logging_configuration`, so blocked and allowed traffic alike leave no record


**EUGUARD_NIS2_001** — Hardcoded secrets detected  
**Mapped to**: NIS2 Art. 21(2)(e) — Secure handling of credentials; GDPR Art. 32(1)(b) — Confidentiality  
**Expected instances**:
- `providers.tf` — `provider "aws"` alias `plain_text_access_keys_provider` has literal `access_key` and `secret_key`
- `ec2.tf` — `user_data` contains `export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE` and `export AWS_SECRET_ACCESS_KEY=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`
- `lambda.tf` — `environment.variables` contains plaintext `access_key` and `secret_key`
- `db-app.tf` — `user_data` contains `DB_PASSWORD=${var.password}` (password interpolation into script)
- `codebuild.tf` — `environment_variable` `DB_PASSWORD` is set to the `var.password` default, not SSM/Secrets Manager

### High Severity

**EUGUARD_GDPR_001** — Provider region outside the EU Sovereign Cloud  
**Mapped to**: GDPR Art. 44 — Transfers of personal data to third countries  
**Expected instances**: `consts.tf` / `providers.tf` — the check only accepts the EU Sovereign Cloud region `eusc-de-east-1`, so every other configured region fails

---

## Summary

**Predicted total mapped findings**: 290–300 across this directory — roughly 50 from the core resource set (12 IAM, 19 S3, 9 RDS, 11 networking), 34 from the additional service coverage (DynamoDB, CloudFront, API Gateway, SNS, Secrets Manager, and Application Load Balancer), 16 from CloudTrail, CodeBuild, and ECS, and 26 from ElastiCache, Aurora, Redshift, and WAFv2. Every check that fires in this directory is mapped, so a scan produces **zero unmapped findings** (measured: 295 mapped).

The actual scan will produce:
1. **`--output dev`**: Terminal rich-table grouped by severity
2. **`--output json`**: Machine-readable findings array
3. **`--output security`**: HTML dashboard with severity breakdown
4. **`--output auditor`**: HTML article-by-article view (NIS2 21(2) and GDPR 32/44 sections)
5. **`--output all`**: Writes all three HTML reports

Run the scan to generate real findings with precise line numbers, resource names, and remediation guidance.
