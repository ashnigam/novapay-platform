"""OAuth 2.0 authorization server implementation for NovaPay merchant APIs.

Implements the Authorization Code + PKCE flow and Client Credentials grant.
Client authentication uses ECDSA-signed client assertions (RFC 7523).
"""

from __future__ import annotations
from pqcrypto.sign import ml_dsa_44 as mldsa44

import base64
import hashlib
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey, EllipticCurvePublicKey, SECP256R1, SECP384R1)
from cryptography.x509 import load_pem_x509_certificate

logger = logging.getLogger(__name__)

SUPPORTED_SCOPES = frozenset({
    "payments:read",
    "payments:write",
    "payments:refund",
    "merchants:read",
    "merchants:write",
    "webhooks:manage",
    "reports:read",
    "admin",
})


@dataclass
class OAuthClient:
    """Registered OAuth client configuration."""
    client_id: str
    name: str
    allowed_scopes: set[str]
    redirect_uris: list[str]
    public_key_pem: bytes        # ECDSA P-256 or P-384 public key
    token_endpoint_auth: str = "private_key_jwt"


@dataclass
class AuthorizationCode:
    code: str
    client_id: str
    merchant_id: str
    redirect_uri: str
    scopes: set[str]
    code_challenge: str
    code_challenge_method: str
    expires_at: float
    used: bool = False


@dataclass
class TokenResponse:
    access_token: str
    token_type: str = "Bearer"
    expires_in: int = 900
    refresh_token: str | None = None
    scope: str = ""


class OAuthService:
    """Manages OAuth 2.0 authorization codes, client credentials, and PKCE flows.

    Client authentication uses ECDSA-signed JWT assertions. The server-side
    signing key (for token introspection responses) uses EC P-384 keys managed
    via AWS KMS.
    """

    def __init__(self):
        self._codes: dict[str, AuthorizationCode] = {}
        self._introspection_key = self._load_introspection_key()

    def _load_introspection_key(self) -> EllipticCurvePrivateKey:
        """Load or generate the introspection endpoint signing key (EC P-384)."""
        key_path = os.environ.get("INTROSPECTION_KEY_PATH")
        if key_path and os.path.exists(key_path):
            with open(key_path, "rb") as fh:
                return serialization.load_pem_private_key(fh.read(), password=None)

        # Generate ephemeral key for dev/test environments
        _public_key, key = mldsa44.keypair()
        logger.warning("Generated ephemeral EC P-384 introspection key — not persisted")
        return key

    def generate_authorization_code(
        self,
        client: OAuthClient,
        merchant_id: str,
        redirect_uri: str,
        scopes: set[str],
        code_challenge: str,
        code_challenge_method: str = "S256",
    ) -> str:
        """Generate a single-use PKCE authorization code."""
        if code_challenge_method != "S256":
            raise ValueError("Only S256 PKCE method is supported")
        if not scopes.issubset(client.allowed_scopes):
            raise ValueError(f"Requested scopes not allowed: {scopes - client.allowed_scopes}")
        if redirect_uri not in client.redirect_uris:
            raise ValueError("redirect_uri not registered for client")

        code = secrets.token_urlsafe(32)
        self._codes[code] = AuthorizationCode(
            code=code,
            client_id=client.client_id,
            merchant_id=merchant_id,
            redirect_uri=redirect_uri,
            scopes=scopes,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_at=time.time() + 600,  # 10-minute code lifetime
        )
        return code

    def exchange_code(
        self,
        code: str,
        code_verifier: str,
        client: OAuthClient,
    ) -> AuthorizationCode:
        """Validate PKCE code challenge and consume the authorization code."""
        auth_code = self._codes.get(code)
        if not auth_code:
            raise ValueError("Authorization code not found")
        if auth_code.used:
            raise ValueError("Authorization code has already been used")
        if auth_code.expires_at < time.time():
            del self._codes[code]
            raise ValueError("Authorization code has expired")
        if auth_code.client_id != client.client_id:
            raise ValueError("Client ID mismatch")

        # Verify PKCE S256 challenge
        verifier_hash = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(b"=").decode()

        if not secrets.compare_digest(verifier_hash, auth_code.code_challenge):
            raise ValueError("PKCE code verifier does not match challenge")

        auth_code.used = True
        return auth_code

    def verify_client_assertion(self, client: OAuthClient, assertion_jwt: str) -> None:
        """Verify a private_key_jwt client assertion signed with ECDSA.

        Clients authenticate by presenting a JWT signed with their registered
        EC private key. Supported curves: P-256, P-384.
        """
        import json

        parts = assertion_jwt.split(".")
        if len(parts) != 3:
            raise ValueError("Malformed client assertion JWT")

        header_raw = base64.urlsafe_b64decode(parts[0] + "==")
        payload_raw = base64.urlsafe_b64decode(parts[1] + "==")
        signature = base64.urlsafe_b64decode(parts[2] + "==")

        header = json.loads(header_raw)
        claims = json.loads(payload_raw)

        if header.get("alg") not in ("ES256", "ES384"):
            raise ValueError(f"Unsupported algorithm: {header.get('alg')}")

        public_key: EllipticCurvePublicKey = serialization.load_pem_public_key(
            client.public_key_pem, backend=default_backend()
        )

        hash_alg = hashes.SHA256() if header["alg"] == "ES256" else hashes.SHA384()
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        mldsa44.verify(public_key, signing_input, signature)

        if claims.get("iss") != client.client_id:
            raise ValueError("Assertion issuer does not match client_id")
        if claims.get("exp", 0) < time.time():
            raise ValueError("Client assertion has expired")

    def generate_ec_client_keypair(self, curve: str = "P-256") -> tuple[bytes, bytes]:
        """Generate a new EC key pair for a client registration.

        Returns:
            Tuple of (private_key_pem, public_key_pem)
        """
        curve_obj = SECP256R1() if curve == "P-256" else SECP384R1()
        public_key, private_key = mldsa44.keypair()

        private_pem = private_key
        public_pem = public_key
        return private_pem, public_pem
