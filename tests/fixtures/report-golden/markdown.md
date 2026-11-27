# tf-eu-guard <VERSION> report

Target: checkov-json:scan.json

| Severity | Findings |
| --- | ---: |
| Critical | 20 |
| High | 17 |
| Medium | 26 |
| Low | 10 |
| Info | 0 |

| Severity | Check | Resource | Location | Articles |
| --- | --- | --- | --- | --- |
| CRITICAL | CKV2_AWS_40 | aws_iam_user_policy.deploy_user_admin | /iam.tf:21 | GDPR Art. 32(1)(b), NIS2 Art. 21(2)(i) |
| CRITICAL | CKV_AWS_286 | aws_iam_user_policy.deploy_user_admin | /iam.tf:21 | GDPR Art. 32(1)(b), NIS2 Art. 21(2)(i) |
| CRITICAL | CKV_AWS_287 | aws_iam_user_policy.deploy_user_admin | /iam.tf:21 | GDPR Art. 32(1)(b), NIS2 Art. 21(2)(i) |
| CRITICAL | CKV_AWS_288 | aws_iam_user_policy.deploy_user_admin | /iam.tf:21 | GDPR Art. 32(1)(b), NIS2 Art. 21(2)(i) |
| CRITICAL | CKV_AWS_289 | aws_iam_user_policy.deploy_user_admin | /iam.tf:21 | GDPR Art. 32(1)(b), NIS2 Art. 21(2)(i) |
| CRITICAL | CKV_AWS_62 | aws_iam_user_policy.deploy_user_admin | /iam.tf:21 | GDPR Art. 32(1)(b), NIS2 Art. 21(2)(i) |
| CRITICAL | CKV_AWS_63 | aws_iam_user_policy.deploy_user_admin | /iam.tf:21 | GDPR Art. 32(1)(b), NIS2 Art. 21(2)(i) |
| CRITICAL | CKV2_AWS_40 | aws_iam_user_policy.deploy_user_iam_escalation | /iam.tf:39 | GDPR Art. 32(1)(b), NIS2 Art. 21(2)(i) |
| CRITICAL | CKV_AWS_286 | aws_iam_user_policy.deploy_user_iam_escalation | /iam.tf:39 | GDPR Art. 32(1)(b), NIS2 Art. 21(2)(i) |
| CRITICAL | CKV_AWS_287 | aws_iam_user_policy.deploy_user_iam_escalation | /iam.tf:39 | GDPR Art. 32(1)(b), NIS2 Art. 21(2)(i) |
| CRITICAL | CKV_AWS_289 | aws_iam_user_policy.deploy_user_iam_escalation | /iam.tf:39 | GDPR Art. 32(1)(b), NIS2 Art. 21(2)(i) |
| CRITICAL | CKV_AWS_288 | aws_iam_user_policy.readonly_user_actually_full_s3 | /iam.tf:62 | GDPR Art. 32(1)(b), NIS2 Art. 21(2)(i) |
| CRITICAL | CKV_AWS_289 | aws_iam_user_policy.readonly_user_actually_full_s3 | /iam.tf:62 | GDPR Art. 32(1)(b), NIS2 Art. 21(2)(i) |
| CRITICAL | CKV_AWS_24 | aws_security_group.web_sg | /network.tf:12 | GDPR Art. 32(1)(b), NIS2 Art. 21(2)(i) |
| CRITICAL | CKV_AWS_24 | aws_security_group.admin_sg | /network.tf:43 | GDPR Art. 32(1)(b), NIS2 Art. 21(2)(i) |
| CRITICAL | CKV_AWS_25 | aws_security_group.admin_sg | /network.tf:43 | GDPR Art. 32(1)(b), NIS2 Art. 21(2)(i) |
| CRITICAL | CKV_AWS_25 | aws_security_group.db_sg | /network.tf:58 | GDPR Art. 32(1)(b), NIS2 Art. 21(2)(i) |
| CRITICAL | CKV_AWS_17 | aws_db_instance.app_db | /rds.tf:6 | GDPR Art. 32(1)(b), NIS2 Art. 21(2)(i) |
| CRITICAL | CKV_AWS_20 | aws_s3_bucket.data | /s3.tf:6 | GDPR Art. 32(1)(b), NIS2 Art. 21(2)(i) |
| CRITICAL | CKV_AWS_70 | aws_s3_bucket_policy.data_public_policy | /s3.tf:26 | GDPR Art. 32(1)(b), NIS2 Art. 21(2)(i) |
| HIGH | CKV_AWS_273 | aws_iam_user.deploy_user | /iam.tf:11 | NIS2 Art. 21(2)(i) |
| HIGH | CKV_AWS_290 | aws_iam_user_policy.deploy_user_admin | /iam.tf:21 | GDPR Art. 32(1)(b), NIS2 Art. 21(2)(i) |
| HIGH | CKV_AWS_355 | aws_iam_user_policy.deploy_user_admin | /iam.tf:21 | GDPR Art. 32(1)(b), NIS2 Art. 21(2)(i) |
| HIGH | CKV_AWS_355 | aws_iam_user_policy.deploy_user_iam_escalation | /iam.tf:39 | GDPR Art. 32(1)(b), NIS2 Art. 21(2)(i) |
| HIGH | CKV_AWS_273 | aws_iam_user.readonly_user | /iam.tf:58 | NIS2 Art. 21(2)(i) |
| HIGH | CKV_AWS_290 | aws_iam_user_policy.readonly_user_actually_full_s3 | /iam.tf:62 | GDPR Art. 32(1)(b), NIS2 Art. 21(2)(i) |
| HIGH | CKV_AWS_355 | aws_iam_user_policy.readonly_user_actually_full_s3 | /iam.tf:62 | GDPR Art. 32(1)(b), NIS2 Art. 21(2)(i) |
| HIGH | CKV_AWS_133 | aws_db_instance.app_db | /rds.tf:6 | GDPR Art. 32(1)(c), NIS2 Art. 21(2)(c) |
| HIGH | CKV_AWS_16 | aws_db_instance.app_db | /rds.tf:6 | GDPR Art. 32(1)(a), NIS2 Art. 21(2)(h) |
| HIGH | CKV2_AWS_6 | aws_s3_bucket.data | /s3.tf:6 | GDPR Art. 32(1)(b) |
| HIGH | CKV_AWS_379 | aws_s3_bucket_acl.data_acl | /s3.tf:10 | GDPR Art. 32(1)(a), NIS2 Art. 21(2)(h) |
| HIGH | CKV_AWS_53 | aws_s3_bucket_public_access_block.data_pab | /s3.tf:15 | GDPR Art. 32(1)(b) |
| HIGH | CKV_AWS_54 | aws_s3_bucket_public_access_block.data_pab | /s3.tf:15 | GDPR Art. 32(1)(b) |
| HIGH | CKV_AWS_55 | aws_s3_bucket_public_access_block.data_pab | /s3.tf:15 | GDPR Art. 32(1)(b) |
| HIGH | CKV_AWS_56 | aws_s3_bucket_public_access_block.data_pab | /s3.tf:15 | GDPR Art. 32(1)(b) |
| HIGH | CKV2_AWS_6 | aws_s3_bucket.logs | /s3.tf:45 | GDPR Art. 32(1)(b) |
| HIGH | CKV2_AWS_6 | aws_s3_bucket.backup_non_eu | /s3.tf:51 | GDPR Art. 32(1)(b) |
| MEDIUM | CKV_AWS_40 | aws_iam_user_policy.deploy_user_admin | /iam.tf:21 | NIS2 Art. 21(2)(i) |
| MEDIUM | CKV_AWS_40 | aws_iam_user_policy.deploy_user_iam_escalation | /iam.tf:39 | NIS2 Art. 21(2)(i) |
| MEDIUM | CKV_AWS_40 | aws_iam_user_policy.readonly_user_actually_full_s3 | /iam.tf:62 | NIS2 Art. 21(2)(i) |
| MEDIUM | CKV2_AWS_11 | aws_vpc.main | /network.tf:3 | NIS2 Art. 21(2)(b) |
| MEDIUM | CKV2_AWS_12 | aws_vpc.main | /network.tf:3 | NIS2 Art. 21(2)(i) |
| MEDIUM | CKV_AWS_260 | aws_security_group.web_sg | /network.tf:12 | NIS2 Art. 21(2)(i) |
| MEDIUM | CKV_AWS_382 | aws_security_group.web_sg | /network.tf:12 | NIS2 Art. 21(2)(i) |
| MEDIUM | CKV_AWS_260 | aws_security_group.admin_sg | /network.tf:43 | NIS2 Art. 21(2)(i) |
| MEDIUM | CKV_AWS_118 | aws_db_instance.app_db | /rds.tf:6 | NIS2 Art. 21(2)(b) |
| MEDIUM | CKV_AWS_129 | aws_db_instance.app_db | /rds.tf:6 | NIS2 Art. 21(2)(b) |
| MEDIUM | CKV_AWS_157 | aws_db_instance.app_db | /rds.tf:6 | GDPR Art. 32(1)(c), NIS2 Art. 21(2)(c) |
| MEDIUM | CKV_AWS_161 | aws_db_instance.app_db | /rds.tf:6 | GDPR Art. 32(1)(b), NIS2 Art. 21(2)(i) |
| MEDIUM | CKV_AWS_226 | aws_db_instance.app_db | /rds.tf:6 | NIS2 Art. 21(2)(e) |

... and 23 more

Unmapped: 0 | Suppressed: 0 | Waived: 0 | Baselined: 0
