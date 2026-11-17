provider "aws" {
  region = "eu-central-1"
}

variable "vault_arn" {
  type = string
}

resource "aws_backup_plan" "offshore" {
  name = "offshore"

  rule {
    rule_name         = "r"
    target_vault_name = "primary"

    copy_action {
      destination_vault_arn = "arn:aws:backup:us-east-2:123456789012:backup-vault:offsite"
    }
  }
}

resource "aws_backup_plan" "unresolved" {
  name = "unresolved"

  rule {
    rule_name         = "r"
    target_vault_name = "primary"

    copy_action {
      destination_vault_arn = var.vault_arn
    }
  }
}

resource "aws_backup_plan" "inside_eu" {
  name = "inside"

  rule {
    rule_name         = "r"
    target_vault_name = "primary"

    copy_action {
      destination_vault_arn = "arn:aws:backup:eu-west-1:123456789012:backup-vault:offsite"
    }
  }
}

resource "aws_ecr_replication_configuration" "offshore" {
  replication_configuration {
    rule {
      destination {
        region      = "us-west-2"
        registry_id = "123456789012"
      }
    }
  }
}

resource "aws_ecr_replication_configuration" "inside_eu" {
  replication_configuration {
    rule {
      destination {
        region      = "eu-north-1"
        registry_id = "123456789012"
      }
    }
  }
}
