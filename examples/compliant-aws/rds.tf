# RDS instance with encryption, backups, IAM auth, and private access
resource "aws_db_instance" "main" {
  identifier     = "${var.environment}-database"
  engine         = "postgres"
  engine_version = "15"
  instance_class = "db.t3.micro"

  allocated_storage = 20
  storage_encrypted = true

  db_name  = "appdb"
  username = "admin"
  manage_master_user_password = true

  backup_retention_period = 7
  deletion_protection     = true
  monitoring_interval     = 60 # enhanced monitoring (CKV_AWS_118)
  skip_final_snapshot     = false
  final_snapshot_identifier = "${var.environment}-database-final"

  auto_minor_version_upgrade = true  # CKV_AWS_226
  copy_tags_to_snapshot      = true  # CKV2_AWS_60
  performance_insights_enabled = true # CKV_AWS_353
  performance_insights_kms_key_id = aws_kms_key.logs.arn # CKV_AWS_354

  publicly_accessible = false
  multi_az            = true

  iam_database_authentication_enabled = true

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  parameter_group_name   = aws_db_parameter_group.main.name

  tags = {
    Environment = var.environment
    Purpose     = "Compliant example"
  }
}

resource "aws_db_subnet_group" "main" {
  name       = "${var.environment}-db-subnet"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]

  tags = {
    Environment = var.environment
  }
}

# Postgres query logging via parameter group (CKV2_AWS_30)
resource "aws_db_parameter_group" "main" {
  name   = "${var.environment}-postgres-params"
  family = "postgres15"

  parameter {
    name  = "log_statement"
    value = "all"
  }

  # Force TLS connections (CKV2_AWS_69)
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  tags = {
    Environment = var.environment
  }
}
