provider "aws" {
  region = "eu-central-1"
}

resource "aws_s3_bucket" "local" {
  bucket = "residency-local"
  region = "eu-central-1"
}

resource "aws_dynamodb_table" "replicated" {
  name         = "replicated"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }

  replica {
    region_name = "eu-west-1"
  }
}

resource "aws_secretsmanager_secret" "replicated" {
  name = "replicated"

  replica {
    region = "eu-north-1"
  }
}
