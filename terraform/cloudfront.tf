# ── CloudFront CDN ────────────────────────────────────────────────────────────
#
# Serves NovaPay's merchant dashboard static assets and client-side bundles.
# Currently using TLSv1.2_2021 security policy. Migration target: custom policy
# with ML-KEM-768 hybrid cipher support once AWS releases CloudFront PQC policies.

resource "aws_cloudfront_distribution" "merchant_dashboard" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "NovaPay Merchant Dashboard CDN - ${var.environment}"
  default_root_object = "index.html"
  aliases             = [var.cdn_domain]
  price_class         = "PriceClass_100"

  origin {
    domain_name = aws_s3_bucket.merchant_dashboard.bucket_regional_domain_name
    origin_id   = "S3-merchant-dashboard"

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.dashboard.cloudfront_access_identity_path
    }
  }

  origin {
    domain_name = aws_lb.api.dns_name
    origin_id   = "ALB-api"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    allowed_methods        = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3-merchant-dashboard"
    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    # TLSv1.2_2021 — supports ECDHE-RSA and ECDHE-ECDSA cipher families
    # TODO: migrate to hybrid PQC policy when available
    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }

    min_ttl     = 0
    default_ttl = 86400
    max_ttl     = 31536000
  }

  ordered_cache_behavior {
    path_pattern           = "/api/*"
    allowed_methods        = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "ALB-api"
    viewer_protocol_policy = "https-only"

    forwarded_values {
      query_string = true
      headers      = ["Authorization", "X-Api-Key", "X-Request-Id"]
      cookies { forward = "none" }
    }

    min_ttl     = 0
    default_ttl = 0
    max_ttl     = 0
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.cdn.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  logging_config {
    include_cookies = false
    bucket          = aws_s3_bucket.cf_logs.bucket_domain_name
    prefix          = "merchant-dashboard/"
  }

  web_acl_id = aws_wafv2_web_acl.main.arn
}

resource "aws_cloudfront_distribution" "payment_sdk" {
  enabled         = true
  is_ipv6_enabled = true
  comment         = "NovaPay Payment SDK CDN - ${var.environment}"
  aliases         = ["sdk.novapay.io"]
  price_class     = "PriceClass_All"

  origin {
    domain_name = aws_s3_bucket.payment_sdk.bucket_regional_domain_name
    origin_id   = "S3-payment-sdk"
    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.sdk.cloudfront_access_identity_path
    }
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "S3-payment-sdk"
    viewer_protocol_policy = "https-only"
    compress               = true

    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }

    min_ttl     = 86400
    default_ttl = 604800
    max_ttl     = 31536000
  }

  restrictions {
    geo_restriction { restriction_type = "none" }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.cdn.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}

resource "aws_cloudfront_origin_access_identity" "dashboard" {
  comment = "OAI for NovaPay merchant dashboard"
}

resource "aws_cloudfront_origin_access_identity" "sdk" {
  comment = "OAI for NovaPay payment SDK bucket"
}

resource "aws_s3_bucket" "merchant_dashboard" {
  bucket = "novapay-merchant-dashboard-${var.environment}"
}

resource "aws_s3_bucket" "payment_sdk" {
  bucket = "novapay-payment-sdk-${var.environment}"
}

resource "aws_s3_bucket" "cf_logs" {
  bucket = "novapay-cf-logs-${var.environment}-${data.aws_caller_identity.current.account_id}"
}

resource "aws_wafv2_web_acl" "main" {
  name  = "novapay-waf-${var.environment}"
  scope = "CLOUDFRONT"

  default_action { allow {} }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "NovapayWAF"
    sampled_requests_enabled   = true
  }
}
