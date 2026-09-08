# S3 bucket with encryption, versioning, and logging
resource "aws_s3_bucket" "data" {
  bucket = "${var.environment}-data-bucket-${data.aws_caller_identity.current.account_id}"

  tags = {
    Environment = var.environment
    Purpose     = "Compliant example"
  }
}

# Enable versioning
resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Enable encryption (KMS, per CKV_AWS_145)
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# Block public access
resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable logging
resource "aws_s3_bucket_logging" "data" {
  bucket = aws_s3_bucket.data.id

  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "data-bucket-logs/"
}

# Logs bucket
resource "aws_s3_bucket" "logs" {
  bucket = "${var.environment}-logs-${data.aws_caller_identity.current.account_id}"

  tags = {
    Environment = var.environment
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_caller_identity" "current" {}

# Lifecycle configuration (CKV2_AWS_61)
resource "aws_s3_bucket_lifecycle_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    id     = "archive-old-objects"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = 3650
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    expiration {
      days = 365
    }
  }
}

# Event notifications: deliver object-created events to an SQS queue (CKV2_AWS_62)
resource "aws_sqs_queue" "s3_events" {
  name                      = "${var.environment}-s3-events"
  sqs_managed_sse_enabled   = true
  message_retention_seconds = 1209600 # 14 days

  tags = {
    Environment = var.environment
  }
}

resource "aws_sqs_queue_policy" "s3_events" {
  queue_url = aws_sqs_queue.s3_events.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.s3_events.arn
        Condition = {
          ArnLike = {
            "aws:SourceArn" = aws_s3_bucket.data.arn
          }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_notification" "data" {
  bucket = aws_s3_bucket.data.id

  queue {
    queue_arn     = aws_sqs_queue.s3_events.arn
    events        = ["s3:ObjectCreated:*"]
    filter_suffix = ".log"
  }
}

resource "aws_s3_bucket_notification" "logs" {
  bucket = aws_s3_bucket.logs.id

  queue {
    queue_arn     = aws_sqs_queue.s3_events.arn
    events        = ["s3:ObjectCreated:*"]
  }
}

# Replication provider (CKV_AWS_144): pinned to the EU Sovereign Cloud —
# the only EUSC region today. True cross-region replication within the
# Sovereign Cloud becomes possible when AWS launches a second EUSC region.
provider "aws" {
  alias  = "replica"
  region = "eusc-de-east-1"
}

resource "aws_s3_bucket" "data_replica" {
  provider = aws.replica
  bucket   = "${var.environment}-data-replica-${data.aws_caller_identity.current.account_id}"

  tags = {
    Environment = var.environment
    Purpose     = "Cross-region replica"
  }
}

resource "aws_s3_bucket_versioning" "data_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.data_replica.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "data_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.data_replica.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_replication_configuration" "data" {
  role   = aws_iam_role.replication.arn
  bucket = aws_s3_bucket.data.id

  rule {
    id     = "replicate-all"
    status = "Enabled"

    destination {
      bucket        = aws_s3_bucket.data_replica.arn
      storage_class = "STANDARD_IA"
    }
  }
}

resource "aws_iam_role" "replication" {
  name = "${var.environment}-s3-replication"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
      }
    ]
  })
}

resource "aws_iam_policy" "replication" {
  name = "${var.environment}-s3-replication"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetReplicationConfiguration",
          "s3:ListBucket"
        ]
        Resource = [aws_s3_bucket.data.arn]
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl"]
        Resource = ["${aws_s3_bucket.data.arn}/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["s3:ReplicateObject", "s3:ReplicateDelete", "s3:ReplicateTags"]
        Resource = ["${aws_s3_bucket.data_replica.arn}/*"]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "replication" {
  role       = aws_iam_role.replication.name
  policy_arn = aws_iam_policy.replication.arn
}

# Replicate the logs bucket to the same replica destination (CKV_AWS_144)
resource "aws_s3_bucket_replication_configuration" "logs" {
  role   = aws_iam_role.replication.arn
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "replicate-logs"
    status = "Enabled"

    destination {
      bucket        = aws_s3_bucket.data_replica.arn
      storage_class = "STANDARD_IA"
      prefix        = "replicated-logs/"
    }
  }
}

# Replica-bucket hygiene: encryption (CKV_AWS_145), access logging (CKV_AWS_18),
# lifecycle (CKV2_AWS_61), event notifications (CKV2_AWS_62)
resource "aws_s3_bucket_server_side_encryption_configuration" "data_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.data_replica.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_logging" "data_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.data_replica.id

  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "data-replica-logs/"
}

resource "aws_s3_bucket_lifecycle_configuration" "data_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.data_replica.id

  rule {
    id     = "archive-old-objects"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }
  }
}

resource "aws_s3_bucket_notification" "data_replica" {
  provider = aws.replica
  bucket   = aws_s3_bucket.data_replica.id

  queue {
    queue_arn = aws_sqs_queue.s3_events.arn
    events    = ["s3:ObjectCreated:*"]
  }
}
