resource "aws_dynamodb_table" "sessions" {
  name           = "${local.resource_prefix.value}-sessions"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "session_id"

  attribute {
    name = "session_id"
    type = "S"
  }

  # CKV_AWS_119: server_side_encryption block omitted entirely, so the
  # table falls back to the AWS-owned key rather than a customer-managed CMK.

  # CKV_AWS_28: no point_in_time_recovery block, so PITR is disabled —
  # a deleted or corrupted session table has no recovery path.
}
