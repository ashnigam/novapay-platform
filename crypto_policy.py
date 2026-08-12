"""Crypto policy — the one place to change your cryptographic algorithms.

Edit a value below to swap an algorithm. Every call site migrated by Qryptive
routes through ``crypto_provider``, which reads these values, so changing one
here changes the algorithm everywhere with NO code migration. This file is
yours: Qryptive generated it; you own and maintain it.

NOTE: changing KEM_ALGORITHM changes the on-wire ML-KEM ciphertext size, so
both sides of a key exchange must adopt the change together.
"""

# Post-quantum signature algorithm (NIST FIPS 204).
# Supported: "ml-dsa-44", "ml-dsa-65", "ml-dsa-87".
SIGNATURE_ALGORITHM = "ml-dsa-65"

# Post-quantum key-encapsulation algorithm (NIST FIPS 203).
# Supported: "ml-kem-512", "ml-kem-768", "ml-kem-1024".
KEM_ALGORITHM = "ml-kem-768"
