resource "aws_cloudfront_distribution" "assets" {
  enabled             = true
  default_root_object = "" # CKV_AWS_305: no default root object configured

  origin {
    domain_name = "${local.resource_prefix.value}-assets.s3.amazonaws.com"
    origin_id   = "assetsOrigin"
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods          = ["GET", "HEAD"]
    target_origin_id        = "assetsOrigin"
    viewer_protocol_policy  = "allow-all" # CKV_AWS_34: should be "https-only" or "redirect-to-https"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  # CKV_AWS_86: no logging_config block — no access logging configured.
  # CKV_AWS_68: no web_acl_id set — no WAF in front of this distribution.

  restrictions {
    geo_restriction {
      restriction_type = "none" # CKV_AWS_374: no geo restriction configured
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version       = "TLSv1" # CKV_AWS_174: below TLS v1.2
  }
}
