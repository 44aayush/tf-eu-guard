output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "s3_bucket_name" {
  description = "S3 data bucket name"
  value       = aws_s3_bucket.data.id
}

output "rds_endpoint" {
  description = "RDS endpoint"
  value       = aws_db_instance.main.endpoint
}

output "iam_user_name" {
  description = "IAM user name"
  value       = aws_iam_user.app_user.name
}

output "flow_log_id" {
  description = "VPC Flow Log ID"
  value       = aws_flow_log.main.id
}
