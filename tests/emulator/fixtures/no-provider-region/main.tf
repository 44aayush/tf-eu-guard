# Emulator fixture: deliberately has no provider block and no region. The AWS
# region comes from AWS_REGION at plan time, which source scanning cannot see
# but plan scanning can (REVIEW.md section 6). The endpoint wiring lives in
# tests/emulator/localstack_override.tf and is copied in at test time only.
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "tf-eu-guard-emulator-data"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}

resource "aws_sqs_queue" "jobs" {
  name                    = "tf-eu-guard-emulator-jobs"
  sqs_managed_sse_enabled = false
}
