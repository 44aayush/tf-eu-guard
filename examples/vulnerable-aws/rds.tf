# RDS instance without encryption, backups, or IAM auth
resource "aws_db_instance" "main" {
  identifier     = "${var.environment}-database"
  engine         = "postgres"
  engine_version = "15"
  instance_class = "db.t3.micro"

  allocated_storage = 20
  storage_encrypted = false

  db_name  = "appdb"
  username = "admin"
  password = var.db_password

  backup_retention_period = 0
  skip_final_snapshot     = true

  publicly_accessible = true
  multi_az            = false

  iam_database_authentication_enabled = false

  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name

  tags = {
    Environment = var.environment
    Purpose     = "Vulnerable example"
  }
}

resource "aws_db_subnet_group" "main" {
  name       = "${var.environment}-db-subnet"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]

  tags = {
    Environment = var.environment
  }
}
