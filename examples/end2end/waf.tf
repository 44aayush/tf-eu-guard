# WAFv2 web ACL that exists but has no rules and no logging, so it provides
# no actual protection despite being "present" in the architecture.
resource "aws_wafv2_web_acl" "app" {
  name  = "${local.resource_prefix.value}-app-waf"
  scope = "REGIONAL"

  default_action {
    allow {} # default-allow with no rules configured below
  }

  visibility_config {
    cloudwatch_metrics_enabled = false # no stock check covers metrics disabled
    metric_name                  = "app-waf"
    sampled_requests_enabled     = false
  }
  # CKV_AWS_192: no AWSManagedRulesKnownBadInputsRuleSet — the Log4j
  #              managed rule group is absent.
  # CKV_AWS_175: no rule blocks at all — the ACL has no associated rules.
  # CKV2_AWS_31: no aws_wafv2_web_acl_logging_configuration for this ACL —
  #              a WAF with no logging can't be used as security evidence
  #              after an incident (graph check).
}
