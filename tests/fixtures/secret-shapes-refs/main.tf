provider "aws" {
  region = "eusc-de-east-1"
}

variable "pw" {
  type      = string
  sensitive = true
}

variable "passwords" {
  type      = map(string)
  sensitive = true
}

variable "env" {
  type = string
}

data "aws_secretsmanager_secret_version" "db" {
  secret_id = "db"
}

resource "random_password" "db" {
  count  = 1
  length = 24
}

# Indirections: must NOT be flagged by EUGUARD_NIS2_001.
resource "aws_db_instance" "ref_jsondecode" {
  password = jsondecode(data.aws_secretsmanager_secret_version.db.secret_string)["password"]
}

resource "aws_db_instance" "ref_indexed_resource" {
  password = random_password.db[0].result
}

resource "aws_db_instance" "ref_map_index" {
  password = var.passwords["db"]
}

resource "aws_db_instance" "ref_try" {
  password = try(var.pw, null)
}

resource "aws_db_instance" "ref_sensitive" {
  password = sensitive(var.pw)
}

resource "aws_db_instance" "ref_interp_only" {
  password = "${var.pw}"
}

resource "aws_db_instance" "ref_plain_var" {
  password = var.pw
}

resource "aws_db_instance" "ref_secret_string" {
  password = data.aws_secretsmanager_secret_version.db.secret_string
}

# Literals: MUST be flagged.
resource "aws_db_instance" "lit_dotted" {
  password = "db_admin.Password1"
}

resource "aws_db_instance" "lit_empty_interp" {
  password = "hunter2${""}"
}

resource "aws_db_instance" "lit_mixed" {
  password = "prod-${var.env}-Hunter2"
}
