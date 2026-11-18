variable "region" {
  type = string
}

provider "aws" {
  region = var.region
}
