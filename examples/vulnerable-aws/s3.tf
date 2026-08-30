# S3 bucket without encryption, versioning, or logging
resource "aws_s3_bucket" "data" {
  bucket = "${var.environment}-data-bucket-${data.aws_caller_identity.current.account_id}"

  tags = {
    Environment = var.environment
    Purpose     = "Vulnerable example"
  }
}

# Public access not blocked
resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Another bucket without encryption
resource "aws_s3_bucket" "logs" {
  bucket = "${var.environment}-logs-${data.aws_caller_identity.current.account_id}"

  tags = {
    Environment = var.environment
  }
}

data "aws_caller_identity" "current" {}
