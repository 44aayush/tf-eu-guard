# tf-eu-guard <VERSION> report

Target: checkov-json:scan.json

| Severity | Findings |
| --- | ---: |
| Critical | 0 |
| High | 1 |
| Medium | 2 |
| Low | 0 |
| Info | 0 |

| Severity | Check | Resource | Location | Articles |
| --- | --- | --- | --- | --- |
| HIGH | CKV_AWS_273 | aws_iam_user.deploy_user | /iam.tf:1 | NIS2 Art. 21(2)(i) |
| MEDIUM | CKV_AWS_40 | aws_iam_user_policy.deploy_user_admin | /iam.tf:5 | NIS2 Art. 21(2)(i) |
| MEDIUM | CKV_AWS_145 | aws_s3_bucket.data | /storage.tf:1 | GDPR Art. 32(1)(a), NIS2 Art. 21(2)(h) |

Unmapped: 2 | Suppressed: 2 | Waived: 0 | Baselined: 0 | Baselined unmapped: 0
