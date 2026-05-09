# ── Lambda Functions ──────────────────────────────────────────────────────────
#
# Serverless functions for webhook processing, async token validation,
# scheduled key rotation jobs, and PCI compliance audit tasks.
# All functions use Python 3.11 runtime with the cryptography package
# for RSA/ECDSA operations.

resource "aws_lambda_function" "webhook_processor" {
  function_name = "novapay-webhook-processor-${var.environment}"
  role          = aws_iam_role.lambda_exec.arn
  runtime       = "python3.11"
  handler       = "handler.lambda_handler"
  timeout       = 30
  memory_size   = var.lambda_memory_mb

  filename         = data.archive_file.webhook_processor.output_path
  source_code_hash = data.archive_file.webhook_processor.output_base64sha256

  environment {
    variables = {
      ENVIRONMENT          = var.environment
      KMS_KEY_ARN          = aws_kms_key.api_token_signing.arn
      PAYMENT_KMS_KEY_ARN  = aws_kms_key.payment_encryption.arn
      LOG_LEVEL            = "INFO"
    }
  }

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.webhook_dlq.arn
  }

  tracing_config {
    mode = "Active"
  }

  tags = { Purpose = "webhook-processing" }
}

resource "aws_lambda_function" "token_validator" {
  function_name = "novapay-token-validator-${var.environment}"
  role          = aws_iam_role.lambda_exec.arn
  runtime       = "python3.11"
  handler       = "token_validator.lambda_handler"
  timeout       = 5
  memory_size   = 256

  filename         = data.archive_file.token_validator.output_path
  source_code_hash = data.archive_file.token_validator.output_base64sha256

  environment {
    variables = {
      ENVIRONMENT     = var.environment
      KMS_KEY_ARN     = aws_kms_key.api_token_signing.arn
      JWT_ALGORITHM   = "RS256"
    }
  }

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }
}

resource "aws_lambda_function" "key_rotation_scheduler" {
  function_name = "novapay-key-rotation-scheduler-${var.environment}"
  role          = aws_iam_role.lambda_exec.arn
  runtime       = "python3.11"
  handler       = "key_rotation.lambda_handler"
  timeout       = 300
  memory_size   = 512

  filename         = data.archive_file.key_rotation.output_path
  source_code_hash = data.archive_file.key_rotation.output_base64sha256

  environment {
    variables = {
      ENVIRONMENT              = var.environment
      PAYMENT_KMS_KEY_ARN      = aws_kms_key.payment_encryption.arn
      DOCUMENT_KMS_KEY_ARN     = aws_kms_key.document_signing.arn
      API_TOKEN_KMS_KEY_ARN    = aws_kms_key.api_token_signing.arn
      ROTATION_NOTIFICATION_SNS = aws_sns_topic.security_alerts.arn
    }
  }
}

resource "aws_lambda_function" "compliance_audit" {
  function_name = "novapay-compliance-audit-${var.environment}"
  role          = aws_iam_role.lambda_exec.arn
  runtime       = "python3.11"
  handler       = "compliance.lambda_handler"
  timeout       = 900
  memory_size   = 1024

  filename         = data.archive_file.compliance_audit.output_path
  source_code_hash = data.archive_file.compliance_audit.output_base64sha256

  environment {
    variables = {
      ENVIRONMENT        = var.environment
      AUDIT_S3_BUCKET    = aws_s3_bucket.audit_logs.id
      KMS_KEY_ARN        = aws_kms_key.secrets.arn
    }
  }
}

# Scheduled execution for key rotation (daily at 02:00 UTC)
resource "aws_cloudwatch_event_rule" "key_rotation" {
  name                = "novapay-key-rotation-${var.environment}"
  description         = "Triggers NovaPay RSA/EC key rotation check"
  schedule_expression = "cron(0 2 * * ? *)"
}

resource "aws_cloudwatch_event_target" "key_rotation" {
  rule      = aws_cloudwatch_event_rule.key_rotation.name
  target_id = "KeyRotationLambda"
  arn       = aws_lambda_function.key_rotation_scheduler.arn
}

resource "aws_lambda_permission" "key_rotation_events" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.key_rotation_scheduler.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.key_rotation.arn
}

resource "aws_iam_role" "lambda_exec" {
  name = "novapay-lambda-exec-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy" "lambda_kms" {
  name = "novapay-lambda-kms-policy-${var.environment}"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"]
        Resource = [
          aws_kms_key.api_token_signing.arn,
          aws_kms_key.payment_encryption.arn,
          aws_kms_key.document_signing.arn,
        ]
      }
    ]
  })
}

resource "aws_security_group" "lambda" {
  name   = "novapay-lambda-sg-${var.environment}"
  vpc_id = aws_vpc.main.id

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_sqs_queue" "webhook_dlq" {
  name                      = "novapay-webhook-dlq-${var.environment}"
  message_retention_seconds = 1209600  # 14 days
}

resource "aws_sns_topic" "security_alerts" {
  name = "novapay-security-alerts-${var.environment}"
}

resource "aws_s3_bucket" "audit_logs" {
  bucket = "novapay-audit-logs-${var.environment}-${data.aws_caller_identity.current.account_id}"
}

data "archive_file" "webhook_processor" {
  type        = "zip"
  source_dir  = "${path.module}/../services/api-gateway/src"
  output_path = "${path.module}/.builds/webhook_processor.zip"
}

data "archive_file" "token_validator" {
  type        = "zip"
  source_dir  = "${path.module}/../services/api-gateway/src"
  output_path = "${path.module}/.builds/token_validator.zip"
}

data "archive_file" "key_rotation" {
  type        = "zip"
  source_dir  = "${path.module}/../services/api-gateway/src"
  output_path = "${path.module}/.builds/key_rotation.zip"
}

data "archive_file" "compliance_audit" {
  type        = "zip"
  source_dir  = "${path.module}/../services/api-gateway/src"
  output_path = "${path.module}/.builds/compliance_audit.zip"
}
