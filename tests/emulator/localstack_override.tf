# Copied into a temporary copy of a fixture at test time; never place it inside
# a scanned fixture (the dummy keys would trigger CKV_AWS_41). The endpoint is
# substituted by tests/emulator/conftest.py (TFEG_EMULATOR_ENDPOINT).
provider "aws" {
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  s3_use_path_style           = true
  endpoints {
    s3       = "@ENDPOINT@"
    sqs      = "@ENDPOINT@"
    dynamodb = "@ENDPOINT@"
    sts      = "@ENDPOINT@"
    iam      = "@ENDPOINT@"
  }
}
