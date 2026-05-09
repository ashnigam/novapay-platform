"""JWT token issuance and validation for NovaPay authentication service.

Implements RS256-signed JWT tokens using RSA-2048 keys loaded from AWS KMS.
Token claims include sub, iss, aud, exp, jti, and custom NovaPay payment scopes.
"""

from __future__ import annotations

import base64
import json
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

logger = logging.getLogger(__name__)

# KMS key ARN for JWT signing — RSA-4096 asymmetric key
_JWT_KMS_KEY_ARN = "arn:aws:kms:us-east-1:123456789012:key/c3d4e5f6-a7b8-4901-cdef-012345678902"

# Token validity windows
_ACCESS_TOKEN_TTL_SECONDS = 900      # 15 minutes
_REFRESH_TOKEN_TTL_SECONDS = 86400   # 24 hours
_SERVICE_TOKEN_TTL_SECONDS = 3600    # 1 hour

ISSUER = "https://auth.novapay.io"
AUDIENCE = ["https://api.novapay.io", "https://payment.novapay.io"]


class JWTHandler:
    """Issues and validates RS256 JWT tokens using AWS KMS asymmetric keys.

    Key material never leaves KMS; signing operations are performed via the
    KMS Sign API. Public key is fetched once and cached for verification.
    """

    def __init__(self, kms_client=None):
        self._kms = kms_client or boto3.client("kms", region_name="us-east-1")
        self._public_key: RSAPublicKey | None = None
        self._public_key_fetched_at: float = 0.0
        self._public_key_ttl = 3600.0  # re-fetch public key every hour

    def _get_public_key(self) -> RSAPublicKey:
        now = time.monotonic()
        if self._public_key is None or (now - self._public_key_fetched_at) > self._public_key_ttl:
            response = self._kms.get_public_key(KeyId=_JWT_KMS_KEY_ARN)
            self._public_key = serialization.load_der_public_key(
                response["PublicKey"], backend=default_backend()
            )
            self._public_key_fetched_at = now
            logger.info("RSA public key refreshed from KMS key %s", _JWT_KMS_KEY_ARN)
        return self._public_key

    def issue_access_token(
        self,
        subject: str,
        merchant_id: str,
        scopes: list[str],
        session_id: str | None = None,
    ) -> str:
        """Issue a short-lived RS256 access token for merchant API access."""
        now = datetime.now(tz=timezone.utc)
        claims = {
            "iss": ISSUER,
            "sub": subject,
            "aud": AUDIENCE,
            "exp": int((now + timedelta(seconds=_ACCESS_TOKEN_TTL_SECONDS)).timestamp()),
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "jti": str(uuid.uuid4()),
            "merchant_id": merchant_id,
            "scope": " ".join(scopes),
            "session_id": session_id or str(uuid.uuid4()),
            "token_type": "access",
        }
        return self._sign_jwt(claims)

    def issue_service_token(self, service_name: str, target_service: str) -> str:
        """Issue a service-to-service authentication token."""
        now = datetime.now(tz=timezone.utc)
        claims = {
            "iss": ISSUER,
            "sub": f"service:{service_name}",
            "aud": [f"https://{target_service}.internal.novapay.io"],
            "exp": int((now + timedelta(seconds=_SERVICE_TOKEN_TTL_SECONDS)).timestamp()),
            "iat": int(now.timestamp()),
            "jti": str(uuid.uuid4()),
            "token_type": "service",
            "service_name": service_name,
        }
        return self._sign_jwt(claims)

    def _sign_jwt(self, claims: dict[str, Any]) -> str:
        """Sign JWT claims via KMS RS256 — private key never leaves KMS."""
        header = {"alg": "RS256", "typ": "JWT", "kid": _JWT_KMS_KEY_ARN.split("/")[-1]}

        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(claims, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

        signing_input = f"{header_b64}.{payload_b64}".encode()

        response = self._kms.sign(
            KeyId=_JWT_KMS_KEY_ARN,
            Message=signing_input,
            MessageType="RAW",
            SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
        )

        sig_b64 = base64.urlsafe_b64encode(response["Signature"]).rstrip(b"=").decode()
        return f"{header_b64}.{payload_b64}.{sig_b64}"

    def validate_token(self, token: str) -> dict[str, Any]:
        """Verify JWT signature with RSA public key and validate standard claims."""
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Malformed JWT: expected 3 dot-separated segments")

        header_b64, payload_b64, sig_b64 = parts

        try:
            header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
            claims = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
            signature = base64.urlsafe_b64decode(sig_b64 + "==")
        except Exception as exc:
            raise ValueError(f"JWT decode error: {exc}") from exc

        if header.get("alg") != "RS256":
            raise ValueError(f"Unsupported algorithm: {header.get('alg')}")

        public_key = self._get_public_key()
        signing_input = f"{header_b64}.{payload_b64}".encode()

        public_key.verify(
            signature,
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )

        now = int(datetime.now(tz=timezone.utc).timestamp())
        if claims.get("exp", 0) < now:
            raise ValueError("Token has expired")
        if claims.get("nbf", now) > now:
            raise ValueError("Token not yet valid")
        if claims.get("iss") != ISSUER:
            raise ValueError(f"Invalid issuer: {claims.get('iss')}")

        return claims


class LocalKeyJWTHandler:
    """Fallback JWT handler using a locally-generated RSA key pair.

    Used in development and integration test environments where KMS
    is not available. NOT for production use.
    """

    def __init__(self, key_size: int = 2048):
        self._private_key: RSAPrivateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )
        self._public_key: RSAPublicKey = self._private_key.public_key()
        logger.warning(
            "LocalKeyJWTHandler initialized — RSA-%d local key in use. "
            "Do not use in production.",
            key_size,
        )

    def get_public_key_pem(self) -> bytes:
        return self._public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())

    def verify(self, message: bytes, signature: bytes) -> None:
        self._public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
