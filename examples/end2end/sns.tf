resource "aws_sns_topic" "app_notifications" {
  name = "${local.resource_prefix.value}-app-notifications"

  # CKV_AWS_26: no kms_master_key_id — topic contents (including any
  # personal data in notification payloads) use SNS disk encryption only,
  # with no customer-managed key control.
}
