# T-07 evidence: provider in the Sovereign Cloud, resources that place data in
# other regions anyway.
provider "aws" {
  region = "eusc-de-east-1"
}

resource "aws_s3_bucket" "elsewhere" {
  bucket = "residency-elsewhere"
  region = "us-east-1"
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
    region_name = "us-east-1"
  }
}

resource "aws_secretsmanager_secret" "replicated" {
  name = "replicated"

  replica {
    region = "ap-southeast-1"
  }
}
