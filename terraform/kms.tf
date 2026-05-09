# ── KMS Key Management ────────────────────────────────────────────────────────
#
# KMS asymmetric keys for payment data encryption, document signing, and
# envelope encryption. All keys use RSA_4096 or ECC_NIST_P384 key specs —
# migration target is ML-KEM / ML-DSA once AWS KMS adds FIPS 203/204 key types.
#
# Key ARNs referenced in application services:
#   Payment encryption : arn:aws:kms:us-east-1:123456789012:key/a1b2c3d4-e5f6-4789-abcd-ef1234567890
#   Document signing   : arn:aws:kms:us-east-1:123456789012:key/b2c3d4e5-f6a7-4890-bcde-f01234567891
#   API token signing  : arn:aws:kms:us-east-1:123456789012:key/c3d4e5f6-a7b8-4901-cdef-012345678902
#   HSM backup key     : arn:aws:kms:us-east-1:123456789012:key/d4e5f6a7-b8c9-4012-defa-123456789013

resource "aws_kms_key" "payment_encryption" {
  description              = "NovaPay payment data envelope encryption key"
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "RSA_4096"
  deletion_window_in_days  = var.kms_deletion_window
  enable_key_rotation      = false  # RSA asymmetric keys don't support auto-rotation

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow payment service"
        Effect = "Allow"
        Principal = { AWS = aws_iam_role.payment_service.arn }
        Action   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "novapay-payment-encryption-${var.environment}"
    DataClass   = "PCI-DSS-Scope"
    KeyPurpose  = "payment-data-encryption"
  }
}

resource "aws_kms_alias" "payment_encryption" {
  name          = "alias/novapay-payment-encryption-${var.environment}"
  target_key_id = aws_kms_key.payment_encryption.key_id
}

resource "aws_kms_key" "document_signing" {
  description              = "NovaPay document and contract signing key"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P384"
  deletion_window_in_days  = var.kms_deletion_window
  enable_key_rotation      = false

  tags = {
    Name       = "novapay-document-signing-${var.environment}"
    DataClass  = "Internal"
    KeyPurpose = "contract-signing"
  }
}

resource "aws_kms_alias" "document_signing" {
  name          = "alias/novapay-document-signing-${var.environment}"
  target_key_id = aws_kms_key.document_signing.key_id
}

resource "aws_kms_key" "api_token_signing" {
  description              = "NovaPay API token signing key (JWT / webhook HMAC)"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_4096"
  deletion_window_in_days  = var.kms_deletion_window
  enable_key_rotation      = false

  tags = {
    Name       = "novapay-api-token-signing-${var.environment}"
    DataClass  = "Confidential"
    KeyPurpose = "api-token-signing"
  }
}

resource "aws_kms_alias" "api_token_signing" {
  name          = "alias/novapay-api-token-signing-${var.environment}"
  target_key_id = aws_kms_key.api_token_signing.key_id
}

resource "aws_kms_key" "secrets" {
  description             = "Envelope key for AWS Secrets Manager — NovaPay secrets"
  key_usage               = "ENCRYPT_DECRYPT"
  deletion_window_in_days = var.kms_deletion_window
  enable_key_rotation     = true  # AES-256 symmetric — rotation supported

  tags = {
    Name       = "novapay-secrets-cmk-${var.environment}"
    DataClass  = "Confidential"
    KeyPurpose = "secrets-envelope"
  }
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/novapay-secrets-cmk-${var.environment}"
  target_key_id = aws_kms_key.secrets.key_id
}

# ── IAM Roles ─────────────────────────────────────────────────────────────────

resource "aws_iam_role" "payment_service" {
  name = "novapay-payment-service-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role" "document_service" {
  name = "novapay-document-service-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}
