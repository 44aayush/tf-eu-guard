# ElastiCache Redis replication group used for session caching, with
# encryption and auth disabled at every layer.
resource "aws_elasticache_replication_group" "sessions" {
  replication_group_id = "${local.resource_prefix.value}-sessions"
  description            = "session cache"
  node_type               = "cache.t3.micro"
  num_cache_clusters      = 1
  engine                  = "redis"

  at_rest_encryption_enabled = false # CKV_AWS_29: no encryption at rest
  transit_encryption_enabled = false # CKV_AWS_30: no encryption in transit
  # CKV_AWS_31: no auth_token set — no Redis AUTH password
  # CKV_AWS_191: no kms_key_id — encryption, if enabled, would use an
  #              AWS owned key rather than a customer-managed one.
  # CKV2_AWS_50: num_cache_clusters = 1 with automatic failover unset —
  #              no Multi-AZ automatic failover (graph check).
}
