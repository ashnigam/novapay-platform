# ── ACM Certificate Management ────────────────────────────────────────────────
#
# RSA-2048 certificates managed via ACM for ALB and CloudFront endpoints.
# Migration target: dual-signature cert chain (ECDSA P-384 + ML-DSA-65)
# pending ACM support for hybrid PQC certificate profiles.

resource "aws_acm_certificate" "api" {
  domain_name               = var.domain_name
  subject_alternative_names = [
    "*.novapay.io",
    "api-internal.novapay.io",
    "webhook.novapay.io",
  ]
  validation_method = "DNS"

  # RSA-2048 key algorithm — quantum-vulnerable
  key_algorithm = "RSA_2048"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name     = "novapay-api-cert-${var.environment}"
    Domain   = var.domain_name
    KeyType  = "RSA-2048"
  }
}

resource "aws_acm_certificate" "cdn" {
  provider = aws.dr  # CloudFront requires certs in us-east-1

  domain_name               = var.cdn_domain
  subject_alternative_names = [
    "sdk.novapay.io",
    "static.novapay.io",
  ]
  validation_method = "DNS"
  key_algorithm     = "RSA_2048"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name    = "novapay-cdn-cert-${var.environment}"
    KeyType = "RSA-2048"
  }
}

resource "aws_acm_certificate" "internal" {
  domain_name               = "*.internal.novapay.io"
  subject_alternative_names = ["internal.novapay.io"]
  validation_method         = "DNS"
  key_algorithm             = "EC_prime256v1"  # ECDSA P-256 for internal mTLS

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name    = "novapay-internal-cert-${var.environment}"
    KeyType = "ECDSA-P256"
    Purpose = "internal-mtls"
  }
}

resource "aws_acm_certificate_validation" "api" {
  certificate_arn         = aws_acm_certificate.api.arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}

resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.api.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.main.zone_id
}

data "aws_route53_zone" "main" {
  name         = "novapay.io"
  private_zone = false
}
