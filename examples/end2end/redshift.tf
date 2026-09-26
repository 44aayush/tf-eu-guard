# Redshift data warehouse cluster with encryption, logging, and public
# access all left at insecure defaults.
resource "aws_redshift_cluster" "analytics" {
  cluster_identifier = "${local.resource_prefix.value}-analytics"
  database_name      = "analytics"
  master_username     = "admin"
  master_password     = var.password
  node_type            = "dc2.large"
  cluster_type         = "single-node"

  publicly_accessible = true  # CKV_AWS_87: publicly accessible
  encrypted            = false # CKV_AWS_64: not encrypted at rest
  # CKV_AWS_142: no kms_key_id — encryption, if enabled, would use an
  #              AWS owned key rather than a customer-managed one.
  # CKV_AWS_71: no logging { } block for audit logging.
  # CKV_AWS_321: no enhanced_vpc_routing — cluster traffic leaves the VPC.
  # CKV_AWS_391: master_username = "admin" combined with public access —
  #              the compound check for a common username on a public cluster.
  # CKV_AWS_154: no cluster_subnet_group_name — deployed outside a VPC.
  skip_final_snapshot  = true  # no stock check: no final snapshot on delete
}
