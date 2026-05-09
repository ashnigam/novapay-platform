# ── Application Load Balancer ─────────────────────────────────────────────────
#
# Terminates TLS for the NovaPay API layer. Currently configured with
# ELBSecurityPolicy-TLS13-1-2-2021-06 which supports ECDHE-RSA and ECDHE-ECDSA
# cipher suites. Migration target: hybrid PQC policy (ML-KEM-768 + ECDHE dual-stack)
# once AWS adds FIPS 203 support to ELB security policies.

resource "aws_lb" "api" {
  name               = "novapay-api-alb-${var.environment}"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  enable_deletion_protection = true
  enable_http2               = true

  access_logs {
    bucket  = aws_s3_bucket.alb_logs.id
    prefix  = "api-alb"
    enabled = true
  }
}

# HTTPS listener — TLS termination point
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.api.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = var.alb_ssl_policy
  certificate_arn   = aws_acm_certificate.api.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

# HTTP → HTTPS redirect
resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.api.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# Internal ALB for service-to-service communication
resource "aws_lb" "internal" {
  name               = "novapay-internal-alb-${var.environment}"
  internal           = true
  load_balancer_type = "application"
  security_groups    = [aws_security_group.internal_alb.id]
  subnets            = aws_subnet.private[*].id
}

resource "aws_lb_listener" "internal_https" {
  load_balancer_arn = aws_lb.internal.arn
  port              = 8443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.internal.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.payment_service.arn
  }
}

resource "aws_lb_target_group" "api" {
  name        = "novapay-api-tg-${var.environment}"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    path                = "/health"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
    matcher             = "200"
  }
}

resource "aws_lb_target_group" "payment_service" {
  name        = "novapay-payment-tg-${var.environment}"
  port        = 8081
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    path = "/health"
  }
}

resource "aws_security_group" "alb" {
  name   = "novapay-alb-sg-${var.environment}"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "internal_alb" {
  name   = "novapay-internal-alb-sg-${var.environment}"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "alb_logs" {
  bucket        = "novapay-alb-logs-${var.environment}-${data.aws_caller_identity.current.account_id}"
  force_destroy = false
}

data "aws_caller_identity" "current" {}
