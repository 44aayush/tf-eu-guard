# ECS clusters, service, and task definition, with container insights,
# Fargate platform version, and public-IP assignment all left insecure.
#
# Two clusters: on the app cluster ECS Exec is overridden to a CMK without an
# encrypted log destination (CKV_AWS_224), and on the batch cluster it is
# disabled outright (CKV_AWS_223). The split is deliberate — CKV_AWS_223 only
# fails on logging = "NONE" while CKV_AWS_224 only fails when logging is not
# "NONE", so the two checks cannot fire on the same resource.
resource "aws_ecs_cluster" "app" {
  name = "${local.resource_prefix.value}-app-cluster"
  # CKV_AWS_65: no setting block enabling containerInsights
  # CKV_AWS_224: execute_command_configuration present with logging overridden
  #   to a CMK, but no log_configuration with
  #   cloud_watch_encryption_enabled / s3_bucket_encryption_enabled, so
  #   session logs are not actually encrypted with that key.

  configuration {
    execute_command_configuration {
      logging = "OVERRIDE"
      kms_key_id = aws_kms_key.logs_key.arn # CKV_AWS_224: CMK set, but...
    }
  }
}

resource "aws_ecs_cluster" "batch" {
  name = "${local.resource_prefix.value}-batch-cluster"
  # CKV_AWS_65: no setting block enabling containerInsights

  configuration {
    execute_command_configuration {
      logging = "NONE" # CKV_AWS_223: ECS Exec sessions are not recorded at all
    }
  }
}

resource "aws_ecs_task_definition" "app" {
  family                   = "${local.resource_prefix.value}-app"
  requires_compatibilities = ["FARGATE"]
  network_mode              = "awsvpc"
  cpu                        = "256"
  memory                     = "512"
  container_definitions      = jsonencode([{
    name  = "app"
    image = "app:latest"
    # CKV_AWS_336: no readonly_root_filesystem — the container can write to
    #              its own root filesystem.
  }])
  # CKV_AWS_249: the task role and the execution role are the same role, so
  #              the container's runtime permissions are not scoped separately
  #              from the ECS agent's infrastructure permissions.
  task_role_arn       = aws_iam_role.ec2role.arn
  execution_role_arn  = aws_iam_role.ec2role.arn
}

resource "aws_ecs_service" "app" {
  name             = "${local.resource_prefix.value}-app-service"
  cluster           = aws_ecs_cluster.app.id
  task_definition    = aws_ecs_task_definition.app.arn
  desired_count      = 1
  launch_type         = "FARGATE"
  platform_version    = "1.3.0" # CKV_AWS_332: not the latest Fargate platform version

  network_configuration {
    subnets          = [aws_subnet.web_subnet.id]
    assign_public_ip = true # CKV_AWS_333: public IP assigned automatically
  }
}
