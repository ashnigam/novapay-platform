"""Crypto provider — algorithm-agile dispatch over a vetted PQC library.

SELECTS algorithms from ``crypto_policy``; never implements cryptography. Every
primitive comes from the audited ``pqcrypto`` package, imported lazily so that an
algorithm you do not use never has to be installed. To change algorithms, edit
``crypto_policy.py`` — never this file. This file is yours: Qryptive generated it.
"""
import importlib

import crypto_policy

# policy name -> pqcrypto module path. Add a future algorithm with ONE row.
_SIGNERS = {
    "ml-dsa-44": "pqcrypto.sign.ml_dsa_44",
    "ml-dsa-65": "pqcrypto.sign.ml_dsa_65",
    "ml-dsa-87": "pqcrypto.sign.ml_dsa_87",
}
_KEMS = {
    "ml-kem-512": "pqcrypto.kem.ml_kem_512",
    "ml-kem-768": "pqcrypto.kem.ml_kem_768",
    "ml-kem-1024": "pqcrypto.kem.ml_kem_1024",
}


def _resolve(registry, name, knob):
    try:
        module_path = registry[name]
    except KeyError:
        raise ValueError(
            "Unknown %s %r in crypto_policy; expected one of %s"
            % (knob, name, sorted(registry))
        )
    try:
        return importlib.import_module(module_path)
    except ImportError as exc:
        raise ImportError(
            "crypto_policy.%s=%r needs %s, which is not installed: %s"
            % (knob, name, module_path, exc)
        )


def _signer():
    return _resolve(_SIGNERS, crypto_policy.SIGNATURE_ALGORITHM, "SIGNATURE_ALGORITHM")


def _kem():
    return _resolve(_KEMS, crypto_policy.KEM_ALGORITHM, "KEM_ALGORITHM")


class _Provider:
    """Algorithm-agile facade for signatures and key exchange."""

    def generate_keypair(self):
        return _signer().generate_keypair()

    def sign(self, secret_key, message):
        return _signer().sign(secret_key, message)

    def verify(self, public_key, message, signature):
        return _signer().verify(public_key, message, signature)

    def kex_initiator(self, peer_public_key):
        return _kem().encrypt(peer_public_key)

    def kex_responder_keypair(self):
        return _kem().generate_keypair()

    def kex_responder_secret(self, private_key, wire_ciphertext):
        return _kem().decrypt(private_key, wire_ciphertext)


provider = _Provider()
