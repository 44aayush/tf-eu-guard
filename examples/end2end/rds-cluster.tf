# Aurora RDS cluster (a distinct resource type from aws_db_instance) with
# encryption, backups, deletion protection, and logging all disabled.
resource "aws_rds_cluster" "aurora" {
  cluster_identifier      = "${local.resource_prefix.value}-aurora"
  engine                   = "aurora-mysql"
  master_username          = "admin"
  master_password          = var.password

  storage_encrypted        = false # CKV_AWS_96: not encrypted at rest
  deletion_protection      = false # CKV_AWS_139: deletion protection disabled
  backup_retention_period  = 1     # CKV_AWS_326: backtracking not enabled
  # CKV_AWS_327: no kms_key_id — storage encryption, if enabled, would use
  #              an AWS owned key rather than a customer-managed one.
  # CKV_AWS_313: no copy_tags_to_snapshot.
  # CKV_AWS_324: no enabled_cloudwatch_logs_exports — no audit/error log export.
  # CKV_AWS_325: no audit logging for the MySQL engine.
  # CKV_AWS_162: iam_database_authentication_enabled = false.
  # CKV2_AWS_8: no AWS Backup plan covers this cluster (graph check).
  iam_database_authentication_enabled = false
}
