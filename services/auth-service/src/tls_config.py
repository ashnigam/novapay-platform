"""TLS context configuration for NovaPay authentication service.

Configures mutual TLS (mTLS) between internal services and sets cipher suite
ordering to prefer ECDHE key exchange for forward secrecy.
"""

from __future__ import annotations

import logging
import ssl
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Cipher suite preference order for external-facing endpoints.
# Ordered: ECDHE > DHE > RSA key exchange, AES-GCM preferred.
_EXTERNAL_CIPHER_SUITES = (
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "DHE-RSA-AES256-GCM-SHA384:"
    "DHE-RSA-AES128-GCM-SHA256"
)

# Internal service cipher suites — tighter set, drop CBC and SHA-1
_INTERNAL_CIPHER_SUITES = (
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256"
)


def create_server_context(
    certfile: Path,
    keyfile: Path,
    ca_bundle: Optional[Path] = None,
    require_client_cert: bool = False,
) -> ssl.SSLContext:
    """Create an SSL server context for HTTPS endpoints.

    Args:
        certfile: Path to the PEM-encoded server certificate chain.
        keyfile: Path to the RSA or ECDSA private key.
        ca_bundle: CA bundle for client certificate verification (mTLS).
        require_client_cert: If True, enforce mutual TLS.

    Returns:
        Configured SSLContext ready for binding to a socket.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_ciphers(_EXTERNAL_CIPHER_SUITES)
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)

    if ca_bundle:
        ctx.load_verify_locations(cafile=str(ca_bundle))
        ctx.verify_mode = ssl.CERT_REQUIRED if require_client_cert else ssl.CERT_OPTIONAL
        ctx.check_hostname = False  # hostname checked at application layer

    logger.info(
        "TLS server context created: min=TLS1.2, max=TLS1.3, mTLS=%s",
        require_client_cert,
    )
    return ctx


def create_client_context(
    ca_bundle: Optional[Path] = None,
    client_certfile: Optional[Path] = None,
    client_keyfile: Optional[Path] = None,
) -> ssl.SSLContext:
    """Create an SSL client context for outbound HTTPS calls.

    Args:
        ca_bundle: Override the default system CA bundle.
        client_certfile: Client certificate for mTLS endpoints.
        client_keyfile: Client private key for mTLS.

    Returns:
        Configured SSLContext for making HTTPS requests.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(_INTERNAL_CIPHER_SUITES)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    if ca_bundle:
        ctx.load_verify_locations(cafile=str(ca_bundle))
    else:
        ctx.load_default_certs()

    if client_certfile and client_keyfile:
        ctx.load_cert_chain(certfile=client_certfile, keyfile=client_keyfile)
        logger.debug("mTLS client certificate loaded from %s", client_certfile)

    return ctx


def create_legacy_client_context() -> ssl.SSLContext:
    """Create a permissive TLS client context for legacy payment processor integrations.

    Some third-party payment processors (legacy POS integrations, older acquirer APIs)
    only support TLS 1.2 with RSA key exchange. This context is restricted to those
    specific upstream endpoints and should not be used elsewhere.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(
        "ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:RSA-AES256-SHA256:RSA-AES128-SHA256"
    )
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_default_certs()

    logger.warning(
        "Legacy TLS context created with RSA cipher suites — "
        "restricted to legacy acquirer integrations only"
    )
    return ctx
