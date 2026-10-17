provider "aws" {
  region = "eusc-de-east-1"
}

# Shapes supported by the focused EUGUARD_NIS2_001 custom check.
resource "aws_db_instance" "database" {
  password = "db-literal"
}

resource "aws_rds_cluster" "rds" {
  master_password = "rds-literal"
}

resource "aws_redshift_cluster" "warehouse" {
  master_password = "redshift-literal"
}

resource "aws_docdb_cluster" "documents" {
  master_password = "docdb-literal"
}

resource "aws_elasticache_replication_group" "cache" {
  auth_token = "cache-literal"
}

resource "aws_codebuild_project" "build" {
  name         = "secret-shape-fixture"
  service_role = "arn:aws:iam::123456789012:role/build"

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                       = "aws/codebuild/standard:7.0"
    type                        = "LINUX_CONTAINER"
    image_pull_credentials_type = "CODEBUILD"

    environment_variable {
      name  = "DB_PASSWORD"
      value = "codebuild-literal"
    }
  }

  source {
    type = "NO_SOURCE"
  }
}

# These shapes are intentionally unsupported by EUGUARD_NIS2_001. The stock
# checks below are the independently verified replacements asserted by tests.
provider "aws" {
  alias      = "credential_shape"
  region     = "eusc-de-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

resource "aws_instance" "user_data_shape" {
  user_data = <<-EOF
    export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
  EOF
}

resource "aws_lambda_function" "environment_shape" {
  function_name = "secret-shape-fixture"
  role          = "arn:aws:iam::123456789012:role/lambda"
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "lambda.zip"

  environment {
    variables = {
      access_key = "AKIAIOSFODNN7EXAMPLE"
      secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    }
  }
}
