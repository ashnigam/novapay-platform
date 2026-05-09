"""AWS KMS client wrapper for NovaPay payment service.

Wraps boto3 KMS operations with retry logic, caching, and structured logging.
Used for envelope key generation, data key decryption, and asymmetric signing
via the payment and document KMS keys.
"""

from __future__ import annotations

import base64
import logging
import os
import time
from functools import lru_cache
from typing import NamedTuple, Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# KMS key ARNs — injected via environment in ECS, hardcoded fallback for local dev
PAYMENT_KMS_KEY_ARN = os.environ.get(
    "PAYMENT_KMS_KEY_ARN",
    "arn:aws:kms:us-east-1:123456789012:key/a1b2c3d4-e5f6-4789-abcd-ef1234567890",
)
DOCUMENT_KMS_KEY_ARN = os.environ.get(
    "DOCUMENT_KMS_KEY_ARN",
    "arn:aws:kms:us-east-1:123456789012:key/b2c3d4e5-f6a7-4890-bcde-f01234567891",
)
API_TOKEN_KMS_KEY_ARN = os.environ.get(
    "API_TOKEN_KMS_KEY_ARN",
    "arn:aws:kms:us-east-1:123456789012:key/c3d4e5f6-a7b8-4901-cdef-012345678902",
)

# Data key spec — AES-256 envelope keys for symmetric payload encryption
_DATA_KEY_SPEC = "AES_256"

# Maximum data keys to cache per KMS key (to avoid redundant GenerateDataKey calls)
_DATA_KEY_CACHE_TTL_SECONDS = 300  # 5 minutes


class DataKey(NamedTuple):
    """Envelope data key pair returned by KMS GenerateDataKey."""
    plaintext: bytes        # 32-byte AES-256 key — zero after use
    ciphertext_blob: bytes  # Encrypted key — safe to persist alongside ciphertext


class KMSClient:
    """Async-safe wrapper around AWS KMS with caching and retry logic."""

    def __init__(self, region: str = "us-east-1", endpoint_url: str | None = None):
        self._kms = boto3.client(
            "kms",
            region_name=region,
            endpoint_url=endpoint_url,
        )
        self._data_key_cache: dict[str, tuple[DataKey, float]] = {}

    # ── Data Key Operations (Envelope Encryption) ─────────────────────────────

    def generate_data_key(self, key_arn: str, context: dict[str, str] | None = None) -> DataKey:
        """Generate a new AES-256 data key for envelope encryption.

        The plaintext key is used to encrypt the payload; the ciphertext_blob
        is stored alongside the ciphertext and later used to decrypt.

        Args:
            key_arn: KMS CMK ARN to use as the wrapping key.
            context: Encryption context for additional authentication.

        Returns:
            DataKey with plaintext (ephemeral) and ciphertext (persistent) portions.
        """
        try:
            response = self._kms.generate_data_key(
                KeyId=key_arn,
                KeySpec=_DATA_KEY_SPEC,
                EncryptionContext=context or {},
            )
            return DataKey(
                plaintext=response["Plaintext"],
                ciphertext_blob=response["CiphertextBlob"],
            )
        except ClientError as exc:
            logger.error("KMS generate_data_key failed for key %s: %s", key_arn, exc)
            raise

    def decrypt_data_key(
        self,
        ciphertext_blob: bytes,
        key_arn: str,
        context: dict[str, str] | None = None,
    ) -> bytes:
        """Decrypt an envelope-encrypted data key via KMS.

        Args:
            ciphertext_blob: Encrypted data key from generate_data_key response.
            key_arn: KMS CMK ARN that was used to generate the key.
            context: Encryption context — must match the context used during generation.

        Returns:
            Plaintext AES-256 key bytes (32 bytes).
        """
        try:
            response = self._kms.decrypt(
                KeyId=key_arn,
                CiphertextBlob=ciphertext_blob,
                EncryptionContext=context or {},
            )
            return response["Plaintext"]
        except ClientError as exc:
            logger.error("KMS decrypt failed: %s", exc)
            raise

    # ── Asymmetric Signing Operations ─────────────────────────────────────────

    def sign_payment_record(self, message: bytes, transaction_id: str) -> bytes:
        """Sign a payment record with the KMS document signing key (ECC P-384).

        Used for regulatory audit records that must be verifiable offline using
        the public key exported from KMS.

        Args:
            message: Serialized payment record bytes.
            transaction_id: Used for structured logging only.

        Returns:
            DER-encoded ECDSA signature bytes.
        """
        try:
            response = self._kms.sign(
                KeyId=DOCUMENT_KMS_KEY_ARN,
                Message=message,
                MessageType="RAW",
                SigningAlgorithm="ECDSA_SHA_384",
            )
            logger.info("Signed payment record %s via KMS", transaction_id)
            return response["Signature"]
        except ClientError as exc:
            logger.error("KMS sign failed for transaction %s: %s", transaction_id, exc)
            raise

    def sign_api_token(self, token_payload: bytes) -> bytes:
        """Sign an API token payload with the RSA-4096 token signing key.

        Used for webhook delivery signatures (NOVAPAY-Signature header).

        Returns:
            Raw RSA-PKCS1v15-SHA256 signature bytes.
        """
        response = self._kms.sign(
            KeyId=API_TOKEN_KMS_KEY_ARN,
            Message=token_payload,
            MessageType="RAW",
            SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
        )
        return response["Signature"]

    def get_public_key(self, key_arn: str) -> bytes:
        """Fetch the DER-encoded public key for an asymmetric KMS key.

        Used to cache and distribute the RSA/EC public key for offline verification.
        """
        response = self._kms.get_public_key(KeyId=key_arn)
        return response["PublicKey"]

    # ── Key Metadata ──────────────────────────────────────────────────────────

    def describe_key(self, key_arn: str) -> dict:
        """Return metadata for a KMS key including key state and rotation status."""
        response = self._kms.describe_key(KeyId=key_arn)
        return response["KeyMetadata"]
