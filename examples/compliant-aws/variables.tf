variable "region" {
  description = "AWS region (EU region for GDPR compliance)"
  type        = string
  default     = "eu-west-1"
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
