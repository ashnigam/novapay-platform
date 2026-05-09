variable "aws_region" {
  description = "Primary AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment (prod, staging, dev)"
  type        = string
  validation {
    condition     = contains(["prod", "staging", "dev"], var.environment)
    error_message = "Environment must be prod, staging, or dev."
  }
}

variable "domain_name" {
  description = "Primary domain name for the platform"
  type        = string
  default     = "api.novapay.io"
}

variable "cdn_domain" {
  description = "CDN domain for static assets"
  type        = string
  default     = "assets.novapay.io"
}

variable "kms_deletion_window" {
  description = "KMS key deletion window in days"
  type        = number
  default     = 30
}

variable "lambda_memory_mb" {
  description = "Memory allocation for Lambda functions (MB)"
  type        = number
  default     = 512
}

variable "alb_ssl_policy" {
  description = "ALB HTTPS listener SSL policy"
  type        = string
  default     = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}
