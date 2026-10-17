provider "aws" {
  region = "eusc-de-east-1"
}

resource "aws_codebuild_project" "literal" {
  name         = "codebuild-secret-literal"
  service_role = "arn:aws:iam::123456789012:role/build"

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/standard:7.0"
    type         = "LINUX_CONTAINER"

    environment_variable {
      name  = "DB_PASSWORD"
      value = "hunter2"
      type  = "PLAINTEXT"
    }
  }

  source {
    type = "NO_SOURCE"
  }
}
