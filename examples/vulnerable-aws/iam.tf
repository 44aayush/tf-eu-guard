# IAM user with inline policy (instead of managed policy)
resource "aws_iam_user" "app_user" {
  name = "${var.environment}-app-user"

  tags = {
    Environment = var.environment
  }
}

# Inline policy with overly broad permissions
resource "aws_iam_user_policy" "app_user_policy" {
  name = "app-access"
  user = aws_iam_user.app_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:*",
          "dynamodb:*",
          "ec2:*"
        ]
        Resource = "*"
      }
    ]
  })
}

# IAM role with overly permissive policy
resource "aws_iam_role" "app_role" {
  name = "${var.environment}-app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Environment = var.environment
  }
}

resource "aws_iam_role_policy" "app_role_policy" {
  name = "app-access"
  role = aws_iam_role.app_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "rds:*"
        Resource = "*"
      }
    ]
  })
}
