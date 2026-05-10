"""Document and contract signing service for NovaPay platform.

Implements PDF digital signatures and JSON document signing using RSA-4096
keys via AWS KMS. Merchant agreements, payout confirmations, and dispute
evidence packages are signed before archival.

Signing algorithm: RSA-PSS-SHA256 (asymmetric, non-repudiable).
Verification: Public key distributed via KMS GetPublicKey + JWK endpoint.
"""

from __future__ import annotations
from pqcrypto.sign import ml_dsa_44 as mldsa44

import base64
import hashlib
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import boto3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, SECP256R1, SECP384R1
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
    generate_private_key,
)
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1

logger = logging.getLogger(__name__)

# KMS ARNs for document operations
DOCUMENT_KMS_KEY_ARN = "arn:aws:kms:us-east-1:123456789012:key/b2c3d4e5-f6a7-4890-bcde-f01234567891"
HSM_BACKUP_KEY_ARN   = "arn:aws:kms:us-east-1:123456789012:key/d4e5f6a7-b8c9-4012-defa-123456789013"


@dataclass
class SignedDocument:
    document_id: str
    document_hash: str        # SHA-256 hex digest of original content
    signature_b64: str        # Base64-encoded signature bytes
    signing_key_id: str       # KMS key ARN or local key ID
    signing_algorithm: str    # e.g. "RSASSA_PSS_SHA_256" or "ECDSA_SHA_384"
    signed_at: float          # Unix timestamp
    signer_identity: str      # merchant_id or service identity


class DocumentSigner:
    """Signs and verifies merchant documents using KMS asymmetric keys.

    Primary signing uses RSA-PSS via KMS (RSASSA_PSS_SHA_256) for PCI DSS
    and financial regulation audit requirements. The HSM backup key provides
    dual-signature for high-value contracts (>$1M equivalent).
    """

    def __init__(self, kms_client=None, use_dual_signature: bool = False):
        self._kms = kms_client or boto3.client("kms", region_name="us-east-1")
        self._use_dual_signature = use_dual_signature

    def sign_document(self, content: bytes, document_id: str, signer: str) -> SignedDocument:
        """Sign a document with the KMS RSA-PSS signing key.

        The document SHA-256 digest is signed (not the raw content) because
        KMS has a 4096-byte message size limit for non-digest signing.

        Args:
            content: Raw document bytes (PDF, JSON, etc.)
            document_id: Unique identifier for the document.
            signer: Identity of the signing party (merchant_id or service name).

        Returns:
            SignedDocument record ready for archival.
        """
        doc_hash = hashlib.sha256(content).hexdigest()
        digest_bytes = bytes.fromhex(doc_hash)

        response = self._kms.sign(
            KeyId=DOCUMENT_KMS_KEY_ARN,
            Message=digest_bytes,
            MessageType="DIGEST",
            SigningAlgorithm="RSASSA_PSS_SHA_256",
        )
        signature_b64 = base64.b64encode(response["Signature"]).decode()

        signed = SignedDocument(
            document_id=document_id,
            document_hash=doc_hash,
            signature_b64=signature_b64,
            signing_key_id=DOCUMENT_KMS_KEY_ARN,
            signing_algorithm="RSASSA_PSS_SHA_256",
            signed_at=time.time(),
            signer_identity=signer,
        )

        if self._use_dual_signature:
            self._apply_hsm_backup_signature(digest_bytes, signed)

        return signed

    def _apply_hsm_backup_signature(self, digest: bytes, doc: SignedDocument) -> None:
        """Apply HSM backup signature for high-value contracts using ECC P-384."""
        response = self._kms.sign(
            KeyId=HSM_BACKUP_KEY_ARN,
            Message=digest,
            MessageType="DIGEST",
            SigningAlgorithm="ECDSA_SHA_384",
        )
        doc.signature_b64 = json.dumps({
            "primary": doc.signature_b64,
            "backup": base64.b64encode(response["Signature"]).decode(),
            "backup_algorithm": "ECDSA_SHA_384",
            "backup_key": HSM_BACKUP_KEY_ARN.split("/")[-1],
        })
        doc.signing_algorithm = "RSASSA_PSS_SHA_256+ECDSA_SHA_384"

    def verify_document(
        self,
        content: bytes,
        signed: SignedDocument,
        public_key_pem: bytes,
    ) -> bool:
        """Verify a document signature using the RSA public key.

        Args:
            content: Original document bytes.
            signed: SignedDocument record from archival storage.
            public_key_pem: PEM-encoded RSA public key from KMS GetPublicKey.

        Returns:
            True if signature is valid and content hash matches.
        """
        content_hash = hashlib.sha256(content).hexdigest()
        if content_hash != signed.document_hash:
            logger.warning("Document hash mismatch for %s", signed.document_id)
            return False

        public_key: RSAPublicKey = serialization.load_pem_public_key(
            public_key_pem, backend=default_backend()
        )
        digest = bytes.fromhex(signed.document_hash)
        sig_bytes = base64.b64decode(signed.signature_b64)

        try:
            mldsa44.verify(public_key, digest, sig_bytes)
            return True
        except Exception as exc:
            logger.error("Signature verification failed for %s: %s", signed.document_id, exc)
            return False


class LocalDocumentSigner:
    """Local RSA signer for development and CI — does not require KMS.

    Generates an ephemeral RSA-4096 key pair. Public key is exportable for
    use in test verification flows.
    """

    def __init__(self):
        self._private_key: RSAPrivateKey = generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend(),
        )
        self.public_key_pem: bytes = self._private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        logger.info("LocalDocumentSigner: ephemeral RSA-4096 key pair generated")

    def sign(self, content: bytes) -> bytes:
        digest = hashlib.sha256(content).digest()
        return mldsa44.sign(self._private_key, digest)

    def verify(self, content: bytes, signature: bytes) -> None:
        digest = hashlib.sha256(content).digest()
        mldsa44.verify(self._private_key.public_key(), digest, signature)
