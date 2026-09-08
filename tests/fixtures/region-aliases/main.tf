# Fixture for the EUGUARD_GDPR_001 live integration test: aliased provider
# blocks covering the classification policy's edge cases — the two eu-prefixed
# third countries, a commercial EU region (GDPR-permissible but outside the
# Sovereign Cloud), the Sovereign Cloud region itself, and a bare variable
# reference with no default (Checkov passes it through unresolved).

provider "aws" {
  alias  = "london"
  region = "eu-west-2"
}

provider "aws" {
  alias  = "zurich"
  region = "eu-central-2"
}

provider "aws" {
  alias  = "frankfurt"
  region = "eu-central-1"
}

provider "aws" {
  alias  = "sovereign"
  region = "eusc-de-east-1"
}

provider "aws" {
  alias  = "bare_variable"
  region = var.region_no_default
}
