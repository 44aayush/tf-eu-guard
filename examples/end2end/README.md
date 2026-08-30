# End-to-End Terragoat Test Suite

## Provenance

These 14 Terraform files are **verbatim copies** from the [bridgecrewio/terragoat](https://github.com/bridgecrewio/terragoat) repository's `terraform/aws/` directory — a deliberately vulnerable AWS infrastructure configuration maintained by Bridgecrew (now part of Palo Alto Networks) for security scanning demonstration and education.

## Purpose

This directory serves as a realistic, comprehensive compliance scanning test case for `tf-eu-guard`. The files intentionally contain dozens of security and compliance violations spanning:

- **IAM**: overpermissive policies, inline policies, hardcoded credentials in provider config
- **S3**: unencrypted buckets, public access, missing logging/versioning
- **RDS/Neptune**: unencrypted storage, public access, no backups, no IAM auth
- **Compute (EC2/Lambda/EKS)**: hardcoded secrets in user-data, unencrypted volumes, overly permissive security groups
- **Network**: security groups open to 0.0.0.0/0, public subnets, missing flow logs
- **Other**: mutable ECR tags, unencrypted Elasticsearch, KMS keys without rotation

## Running the Scan

From the repository root, execute:

```bash
tf-eu-guard scan examples/end2end --output all
```

This will:
1. Run Checkov against all `.tf` files in this directory
2. Enrich failed checks with NIS2 (Directive 2022/2555 Art. 21(2)) and GDPR (Regulation 2016/679 Art. 32(1), Art. 44) compliance mappings
3. Generate three HTML reports:
   - `dev-report.html` — terminal-style output for developers
   - `scan-report.html` — dashboard sorted by severity (CRITICAL/HIGH/MEDIUM/LOW)
   - `auditor-report.html` — article-by-article compliance view for auditors

**Expected finding count**: 30+ mapped violations (the exact count depends on the current registry coverage).

## Note on AWS Credentials

Several files (`providers.tf`, `ec2.tf`, `lambda.tf`) contain AWS access keys like:
- `AKIAIOSFODNN7EXAMPLE`
- `AKIAIOSFODNN7EXAMPLE`
- `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMAAAKEY`

These are **intentional public test fixtures** from AWS documentation examples, not real secrets. They appear in the official [AWS SDK examples](https://docs.aws.amazon.com/sdk-for-javascript/v2/developer-guide/loading-node-credentials-shared.html) and are safe to commit. The custom check `EUGUARD_NIS2_001` will still flag them (correctly, as the pattern-match heuristic cannot distinguish fixtures from real leaks).

## Files

- **consts.tf** — variables, locals, data sources (caller identity, AMI)
- **providers.tf** — AWS provider config (includes hardcoded test credentials in second provider)
- **s3.tf** — 5 buckets with various misconfigurations
- **iam.tf** — IAM user with inline policy granting `*:*`
- **rds.tf** — 9 RDS clusters with missing encryption/backups
- **kms.tf** — KMS key without rotation
- **elb.tf** — Load balancer with HTTP-only listener
- **es.tf** — Unencrypted Elasticsearch 2.3 domain
- **lambda.tf** — Lambda function with plaintext secrets in environment variables
- **neptune.tf** — Neptune cluster without encryption or IAM auth
- **ecr.tf** — ECR repository with mutable image tags
- **eks.tf** — EKS cluster, VPC, subnets (public IPs enabled)
- **db-app.tf** — RDS instance + EC2 app server with database password in user-data
- **ec2.tf** — EC2 instance with hardcoded AWS keys in user-data, unencrypted EBS, security group open to world

## Maintenance

Do not edit these files to "fix" vulnerabilities — their purpose is to remain vulnerable for testing. For a **compliant** reference implementation, see `examples/compliant-aws/` instead.

Last synchronized: 2026-08-26 from terragoat commit history (git tags in each resource reflect original authorship).
