provider "aws" {
  region = "eusc-de-east-1"
}

variable "db_password" {
  type      = string
  sensitive = true
}

variable "managed_password" {
  type      = string
  sensitive = true
}

data "aws_secretsmanager_secret_version" "db" {
  secret_id = "example/database"
}

resource "aws_ssm_parameter" "password" {
  name  = "/example/database/password"
  type  = "SecureString"
  value = var.managed_password
}

resource "aws_codebuild_project" "reference" {
  name         = "codebuild-secret-reference"
  service_role = "arn:aws:iam::123456789012:role/build"

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/standard:7.0"
    type         = "LINUX_CONTAINER"

    environment_variable {
      name  = "DB_PASSWORD_VAR"
      value = var.db_password
      type  = "PLAINTEXT"
    }

    environment_variable {
      name  = "DB_PASSWORD_DATA"
      value = data.aws_secretsmanager_secret_version.db.secret_string
      type  = "PLAINTEXT"
    }

    environment_variable {
      name  = "DB_PASSWORD_RESOURCE"
      value = aws_ssm_parameter.password.value
      type  = "PLAINTEXT"
    }

    environment_variable {
      name  = "DB_PASSWORD_INTERPOLATED"
      value = "${var.db_password}"
      type  = "PLAINTEXT"
    }
  }

  source {
    type = "NO_SOURCE"
  }
}
