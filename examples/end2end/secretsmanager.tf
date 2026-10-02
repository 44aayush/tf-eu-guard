resource "aws_secretsmanager_secret" "db_password" {
  name = "${local.resource_prefix.value}-db-password"

  # CKV_AWS_149: no kms_key_id — falls back to the account default
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = var.password
}
