resource "aws_api_gateway_rest_api" "app" {
  name = "${local.resource_prefix.value}-app-api"
}

resource "aws_api_gateway_deployment" "app" {
  rest_api_id = aws_api_gateway_rest_api.app.id
  triggers = {
    redeployment = sha1(jsonencode(aws_api_gateway_rest_api.app.body))
  }
}

resource "aws_api_gateway_stage" "prod" {
  deployment_id = aws_api_gateway_deployment.app.id
  rest_api_id   = aws_api_gateway_rest_api.app.id
  stage_name    = "prod"

  xray_tracing_enabled = false # CKV_AWS_73: X-Ray tracing disabled

  # CKV_AWS_76: no access_log_settings block — no access logging.
  # CKV_AWS_120: no cache_cluster_enabled — response caching disabled.
}

resource "aws_api_gateway_method_settings" "prod" {
  rest_api_id = aws_api_gateway_rest_api.app.id
  stage_name  = aws_api_gateway_stage.prod.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled = true
    logging_level   = "INFO"
    data_trace_enabled = true # CKV_AWS_276: full request/response bodies logged
    caching_enabled     = false # CKV_AWS_225: method-level caching disabled
  }
}
