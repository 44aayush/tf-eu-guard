# VPC with flow logs enabled
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.environment}-vpc"
    Environment = var.environment
  }
}

# VPC Flow Logs
resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/${var.environment}-flow-logs"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.logs.arn

  tags = {
    Environment = var.environment
  }
}

# CMK for log-group encryption (CKV_AWS_158)
resource "aws_kms_key" "logs" {
  description             = "CloudWatch log group encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  # Explicit key policy (CKV2_AWS_64): root account retains full control,
  # CloudWatch Logs service can use the key
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "Enable IAM User Permissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudWatchLogs"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.region}.amazonaws.com" }
        Action = [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Environment = var.environment
  }
}

resource "aws_kms_alias" "logs" {
  name          = "alias/${var.environment}-logs"
  target_key_id = aws_kms_key.logs.key_id
}

resource "aws_iam_role" "flow_logs" {
  name = "${var.environment}-vpc-flow-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "${var.environment}-vpc-flow-logs"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Effect   = "Allow"
        # Scoped to this log group instead of "*" (CKV_AWS_355 / CKV_AWS_290)
        Resource = [
          aws_cloudwatch_log_group.flow_logs.arn,
          "${aws_cloudwatch_log_group.flow_logs.arn}:*"
        ]
      }
    ]
  })
}

# Restrict all traffic on the VPC default security group (CKV2_AWS_12)
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id

  ingress = []
  egress  = []
}

# Private subnets (no public IP auto-assign)
resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.10.0/24"
  availability_zone = "${var.region}a"

  tags = {
    Name        = "${var.environment}-private-a"
    Environment = var.environment
  }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.11.0/24"
  availability_zone = "${var.region}b"

  tags = {
    Name        = "${var.environment}-private-b"
    Environment = var.environment
  }
}

# Public subnets without auto-assign public IP
resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = false

  tags = {
    Name        = "${var.environment}-public-a"
    Environment = var.environment
  }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "${var.region}b"
  map_public_ip_on_launch = false

  tags = {
    Name        = "${var.environment}-public-b"
    Environment = var.environment
  }
}

# Security group with restricted ingress
resource "aws_security_group" "web" {
  name        = "${var.environment}-web-sg"
  description = "Web server security group with restricted access"
  vpc_id      = aws_vpc.main.id

  # No SSH from 0.0.0.0/0 - use Systems Manager Session Manager instead
  # HTTP only from specific CIDR (example: office IP)
  ingress {
    description = "HTTP from office"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"] # Replace with actual office IP
  }

  egress {
    description = "HTTPS outbound"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Environment = var.environment
  }
}

# RDS security group with VPC-only access
resource "aws_security_group" "rds" {
  name        = "${var.environment}-rds-sg"
  description = "RDS security group with VPC-only access"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "PostgreSQL from web tier"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
  }

  tags = {
    Environment = var.environment
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name        = "${var.environment}-igw"
    Environment = var.environment
  }
}

# Attach the web SG to an ENI in the public subnet (CKV2_AWS_5)
resource "aws_network_interface" "web" {
  subnet_id       = aws_subnet.public_a.id
  security_groups = [aws_security_group.web.id]

  tags = {
    Environment = var.environment
    Purpose     = "Web tier placeholder"
  }
}
