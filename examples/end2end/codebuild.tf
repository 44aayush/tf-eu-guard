# CodeBuild project with plaintext environment variables and no encryption
# configured for build artifacts.
resource "aws_codebuild_project" "app" {
  name          = "${local.resource_prefix.value}-app-build"
  service_role   = aws_iam_role.build_role.arn

  artifacts {
    type           = "S3"
    location       = "${local.resource_prefix.value}-build-artifacts"
    packaging      = "ZIP"
    # CKV_AWS_147: no encryption_key — build output is not KMS-encrypted.
  }

  environment {
    compute_type                = "BUILD_GENERAL1_SMALL"
    image                        = "aws/codebuild/standard:5.0"
    type                         = "LINUX_CONTAINER"
    privileged_mode              = true # CKV_AWS_316: privileged mode enabled

    environment_variable {
      name  = "DB_PASSWORD"
      value = var.password # EUGUARD_NIS2_001: secret passed as a plaintext env var, not SSM/Secrets Manager
    }
  }

  source {
    type     = "GITHUB"
    location = "https://github.com/example/app.git"
  }
  # CKV_AWS_147: no encryption_key set for build output artifacts.
  # CKV_AWS_314: no logs_config block — build logs are not exported.
}

resource "aws_iam_role" "build_role" {
  name = "${local.resource_prefix.value}-codebuild-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "codebuild.amazonaws.com" }
    }]
  })
}
