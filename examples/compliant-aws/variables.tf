variable "region" {
  description = "AWS region (EU Sovereign Cloud region for this project's data-residency policy)"
  type        = string
  default     = "eusc-de-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "demo"
}

variable "db_password_secret_arn" {
  description = "ARN of Secrets Manager secret containing database password"
  type        = string
}
