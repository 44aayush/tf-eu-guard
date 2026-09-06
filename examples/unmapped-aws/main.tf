# Deliberately mixes mapped and UNMAPPED Checkov failures.
#
# The aws_iam_account_password_policy below fails the password-policy check
# family (CKV_AWS_10/11/12/13/14/15, ...) which is intentionally NOT in the
# mapping registry (see docs/check-mapping-table.md, "Checks still
# intentionally unmapped"). The S3 bucket fails mapped checks
# (CKV_AWS_145 encryption, CKV_AWS_18 access logging, ...).
#
# This fixture is the regression test for the unmapped-findings contract:
# a scan must report the bucket findings as mapped AND surface the password
# policy failures as present-but-unmapped — never silently drop them.

resource "aws_iam_account_password_policy" "weak" {
  minimum_password_length    = 8
  require_lowercase          = false
  require_uppercase          = false
  require_numbers            = false
  require_symbols            = false
  password_reuse_prevention  = 1
  max_password_age           = 365
}

resource "aws_s3_bucket" "data" {
  bucket = "unmapped-fixture-bucket"
  # no server-side encryption, no logging -> mapped CKV_AWS_* failures
}
