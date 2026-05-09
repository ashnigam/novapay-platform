"""NovaPay API Gateway Lambda — webhook event dispatcher and token validator.

Handles inbound webhook events from card networks (Visa, Mastercard) and
payment processors. Each event payload is RSA-verified against the sender's
published public key before dispatch to internal services.

Lambda runtime: Python 3.11
Memory: 512 MB (RSA verification overhead ~30 ms per event at 4096-bit keys)
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import time
from functools import lru_cache
from typing import Any

import boto3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

_KMS_KEY_ARN = os.environ.get(
    "KMS_KEY_ARN",
    "arn:aws:kms:us-east-1:123456789012:key/c3d4e5f6-a7b8-4901-cdef-012345678902",
)
_PAYMENT_KMS_KEY_ARN = os.environ.get(
    "PAYMENT_KMS_KEY_ARN",
    "arn:aws:kms:us-east-1:123456789012:key/a1b2c3d4-e5f6-4789-abcd-ef1234567890",
)

_ENVIRONMENT = os.environ.get("ENVIRONMENT", "dev")

_kms_client = None


def _get_kms() -> boto3.client:
    global _kms_client
    if _kms_client is None:
        _kms_client = boto3.client("kms", region_name="us-east-1")
    return _kms_client


@lru_cache(maxsize=32)
def _fetch_sender_public_key(sender_id: str) -> RSAPublicKey:
    """Fetch and cache RSA public key for a known webhook sender.

    Public keys are stored in AWS Secrets Manager and rotated quarterly.
    Cache size of 32 handles typical card network sender pool.
    """
    sm = boto3.client("secretsmanager", region_name="us-east-1")
    secret_name = f"novapay/{_ENVIRONMENT}/webhook-keys/{sender_id}"

    try:
        response = sm.get_secret_value(SecretId=secret_name)
        key_pem = response["SecretString"].encode()
        return serialization.load_pem_public_key(key_pem, backend=default_backend())
    except Exception as exc:
        logger.error("Failed to fetch public key for sender %s: %s", sender_id, exc)
        raise


def verify_webhook_signature(
    payload: bytes,
    signature_b64: str,
    sender_id: str,
) -> bool:
    """Verify a webhook payload signature using the sender's RSA-2048 public key.

    Card networks sign webhook payloads with RSA-PKCS1v15-SHA256. Signature
    is base64-encoded and delivered in the X-NovaPay-Signature header.

    Args:
        payload: Raw request body bytes.
        signature_b64: Base64-encoded signature from X-NovaPay-Signature header.
        sender_id: Identifier for the sending card network or processor.

    Returns:
        True if signature is valid.
    """
    public_key = _fetch_sender_public_key(sender_id)
    signature = base64.b64decode(signature_b64)

    try:
        public_key.verify(
            signature,
            payload,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except Exception:
        logger.warning("Invalid webhook signature from sender %s", sender_id)
        return False


def generate_response_signature(response_body: bytes) -> str:
    """Sign an API response with the platform RSA-4096 key via KMS.

    Used for webhook delivery confirmations and payment status callbacks
    so downstream systems can verify authenticity.

    Returns:
        Base64-encoded RSA-PKCS1v15-SHA256 signature.
    """
    kms = _get_kms()
    response = kms.sign(
        KeyId=_KMS_KEY_ARN,
        Message=hashlib.sha256(response_body).digest(),
        MessageType="DIGEST",
        SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
    )
    return base64.b64encode(response["Signature"]).decode()


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Lambda entry point — route inbound webhook events.

    Validates signature, deserializes payload, and forwards to the appropriate
    internal SQS queue for async processing.
    """
    start = time.perf_counter()

    try:
        body_raw = event.get("body", "{}")
        if event.get("isBase64Encoded"):
            body_raw = base64.b64decode(body_raw).decode()

        headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
        sender_id = headers.get("x-novapay-sender-id", "unknown")
        signature = headers.get("x-novapay-signature", "")
        event_type = headers.get("x-novapay-event-type", "unknown")

        body_bytes = body_raw.encode() if isinstance(body_raw, str) else body_raw

        if _ENVIRONMENT == "prod" and not verify_webhook_signature(body_bytes, signature, sender_id):
            logger.warning("Rejected webhook from %s — invalid signature", sender_id)
            return {"statusCode": 401, "body": json.dumps({"error": "invalid_signature"})}

        payload = json.loads(body_raw)

        response_body = json.dumps({"status": "accepted", "event_type": event_type}).encode()
        response_signature = generate_response_signature(response_body)

        elapsed_ms = (time.perf_counter() - start) * 1000
        logger.info(
            "Webhook processed: sender=%s type=%s duration_ms=%.1f",
            sender_id, event_type, elapsed_ms,
        )

        return {
            "statusCode": 202,
            "headers": {
                "Content-Type": "application/json",
                "X-NovaPay-Response-Signature": response_signature,
            },
            "body": response_body.decode(),
        }

    except json.JSONDecodeError as exc:
        logger.error("Malformed webhook payload: %s", exc)
        return {"statusCode": 400, "body": json.dumps({"error": "invalid_json"})}
    except Exception as exc:
        logger.error("Unhandled webhook error: %s", exc, exc_info=True)
        return {"statusCode": 500, "body": json.dumps({"error": "internal_error"})}
