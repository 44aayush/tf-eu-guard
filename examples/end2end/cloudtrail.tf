# Account-level CloudTrail with log-file validation, multi-region coverage,
# CloudWatch Logs integration, and KMS encryption all left disabled.
resource "aws_cloudtrail" "account_trail" {
  name                          = "${local.resource_prefix.value}-account-trail"
  s3_bucket_name                = "${local.resource_prefix.value}-cloudtrail-logs"

  enable_log_file_validation    = false # CKV_AWS_36: log file validation disabled
  is_multi_region_trail         = false # CKV_AWS_67: single-region trail only
  # CKV_AWS_35: no kms_key_id — trail logs are not KMS-encrypted
  # CKV_AWS_252: no sns_topic_name — no notification on new log delivery
  # CKV2_AWS_10: no cloud_watch_logs_role_arn / cloud_watch_logs_group_arn —
  #              the trail is not integrated with CloudWatch Logs
}
