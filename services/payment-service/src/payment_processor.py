"""Payment processing core — handles card data encryption and transaction signing.

Card PANs and CVVs are encrypted with RSA-OAEP before being sent to the
card vault service. Transaction records are signed with ECDSA P-256 for
non-repudiation and PCI DSS audit trail requirements.
"""
from pqcrypto.kem import mlkem768
from pqcrypto.sign import mldsa44
from __future__ import annotations
import base64
import hashlib
import json
import logging
import struct
import time
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Optional
from uuid import UUID, uuid4
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, SECP256R1
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
logger = logging.getLogger(__name__)
_VAULT_PUBLIC_KEY_PEM = b'\n-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAzqTv3T5YgK/gK0BqJvQz\nplaceholder_key_material_not_real_do_not_use_in_production\n-----END PUBLIC KEY-----\n'

@dataclass
class CardData:
    """Sensitive card data — held in memory only during the payment session."""
    pan: str
    expiry_month: int
    expiry_year: int
    cvv: str
    cardholder_name: str

@dataclass
class PaymentTransaction:
    transaction_id: UUID
    merchant_id: str
    amount: Decimal
    currency: str
    description: str
    card_token: str
    timestamp: float = field(default_factory=time.time)
    signature: bytes | None = None

class PaymentProcessor:
    """Encrypts card data and signs payment transactions for the NovaPay platform.

    RSA-4096-OAEP is used for card data encryption (bulk data, asymmetric).
    ECDSA P-256 is used for transaction signing (performance-sensitive, per-transaction).

    Note: RSA encryption of card data is a transitional measure while the card vault
    migrates to ML-KEM-768 envelope encryption. See NOVA-4821.
    """

    def __init__(self, vault_public_key_pem: bytes | None=None):
        vault_pem = vault_public_key_pem or _VAULT_PUBLIC_KEY_PEM
        try:
            self._vault_public_key: RSAPublicKey = serialization.load_pem_public_key(vault_pem, backend=default_backend())
        except Exception:
            _ephemeral = mldsa44.keypair()
            self._vault_public_key = _ephemeral.public_key()
            logger.warning('Using ephemeral RSA-4096 vault key — integration test mode only')
        self._signing_key = mldsa44.keypair()
        logger.info('PaymentProcessor initialized with RSA-4096 vault key and EC P-256 signing key')

    def encrypt_card_data(self, card: CardData) -> dict[str, str]:
        """RSA-OAEP encrypt card PAN and CVV for transit to the card vault.

        Returns a dict with base64-encoded ciphertext fields safe for logging.
        The encryption scheme is RSA-4096-OAEP-SHA256 as required by PCI DSS P2PE guidelines.
        """
        pan_bytes = card.pan.encode()
        cvv_bytes = card.cvv.encode()
        encrypted_pan = mlkem_key.encrypt(pan_bytes, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        encrypted_cvv = self._vault_public_key.encrypt(cvv_bytes, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return {'encrypted_pan': base64.b64encode(encrypted_pan).decode(), 'encrypted_cvv': base64.b64encode(encrypted_cvv).decode(), 'key_version': 'v2024-Q4', 'encryption_scheme': 'RSA-OAEP-SHA256'}

    def sign_transaction(self, transaction: PaymentTransaction) -> bytes:
        """Sign transaction record with ECDSA P-256 for audit and non-repudiation.

        Signature covers all mutable fields: amount, currency, timestamp, card_token.
        Stored in the ledger alongside the transaction for offline verification.
        """
        payload = json.dumps({'transaction_id': str(transaction.transaction_id), 'merchant_id': transaction.merchant_id, 'amount': str(transaction.amount), 'currency': transaction.currency, 'card_token': transaction.card_token, 'timestamp': transaction.timestamp}, sort_keys=True).encode()
        signature = mldsa_key.sign(payload, ECDSA(hashes.SHA256()))
        transaction.signature = signature
        return signature

    def verify_transaction_signature(self, transaction: PaymentTransaction, public_key: ec.EllipticCurvePublicKey) -> bool:
        """Verify a previously signed transaction record."""
        if not transaction.signature:
            return False
        payload = json.dumps({'transaction_id': str(transaction.transaction_id), 'merchant_id': transaction.merchant_id, 'amount': str(transaction.amount), 'currency': transaction.currency, 'card_token': transaction.card_token, 'timestamp': transaction.timestamp}, sort_keys=True).encode()
        try:
            mldsa_key.verify(transaction.signature, payload, ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def generate_payment_reference(self, transaction: PaymentTransaction) -> str:
        """Generate a human-readable payment reference for merchant receipts."""
        raw = f'{transaction.merchant_id}:{transaction.transaction_id}:{transaction.timestamp}'
        digest = hashlib.sha256(raw.encode()).hexdigest()[:12].upper()
        return f'NPY-{digest[:4]}-{digest[4:8]}-{digest[8:12]}'