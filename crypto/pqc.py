"""
Post-quantum cryptography wrapper using liboqs.
ML-DSA-65 for signatures (replaces Ed25519).
ML-KEM-768 for key encapsulation (replaces ECDH).

Requires the liboqs C library, available only inside the Docker image
openquantumsafe/liboqs-python:latest.

When running outside Docker this module falls back to Ed25519 via the
cryptography library and sets PQC_AVAILABLE = False so callers can detect it.
"""

import warnings

try:
    import oqs  # noqa: F401 — only imported here, never elsewhere
    PQC_AVAILABLE = True
except (ImportError, RuntimeError):
    PQC_AVAILABLE = False

# ── Signatures (ML-DSA-65) ────────────────────────────────────────────────────


def generate_keypair() -> tuple[bytes, bytes]:
    """Return (private_key_bytes, public_key_bytes)."""
    if PQC_AVAILABLE:
        with oqs.Signature("ML-DSA-65") as signer:
            public_key = signer.generate_keypair()
            private_key = signer.export_secret_key()
        return private_key, public_key
    else:
        warnings.warn("liboqs not available — using Ed25519 (NOT post-quantum secure)")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )
        priv = Ed25519PrivateKey.generate()
        priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return priv_bytes, pub_bytes


def sign(private_key_bytes: bytes, message: bytes) -> bytes:
    """Sign message; return signature bytes."""
    if PQC_AVAILABLE:
        with oqs.Signature("ML-DSA-65", private_key_bytes) as signer:
            return signer.sign(message)
    else:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        return Ed25519PrivateKey.from_private_bytes(private_key_bytes).sign(message)


def verify(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Verify signature; return True if valid, False on any error."""
    try:
        if PQC_AVAILABLE:
            with oqs.Signature("ML-DSA-65") as verifier:
                return verifier.verify(message, signature, public_key_bytes)
        else:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            pub = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            pub.verify(signature, message)
            return True
    except Exception:
        return False


# ── Key Encapsulation (ML-KEM-768) ────────────────────────────────────────────


def kem_generate_keypair() -> tuple[bytes, bytes]:
    """Return (private_key_bytes, public_key_bytes)."""
    if PQC_AVAILABLE:
        with oqs.KeyEncapsulation("ML-KEM-768") as kem:
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()
        return private_key, public_key
    else:
        import secrets
        warnings.warn("liboqs not available — KEM using random key (NOT secure)")
        key = secrets.token_bytes(32)
        return key, key


def kem_encapsulate(recipient_public_key: bytes) -> tuple[bytes, bytes]:
    """Return (ciphertext, shared_secret_32_bytes)."""
    if PQC_AVAILABLE:
        with oqs.KeyEncapsulation("ML-KEM-768") as kem:
            ciphertext, shared_secret = kem.encap_secret(recipient_public_key)
        return ciphertext, shared_secret[:32]
    else:
        import secrets
        shared_secret = secrets.token_bytes(32)
        return shared_secret, shared_secret


def kem_decapsulate(private_key_bytes: bytes, ciphertext: bytes) -> bytes:
    """Return shared_secret_32_bytes."""
    if PQC_AVAILABLE:
        with oqs.KeyEncapsulation("ML-KEM-768", private_key_bytes) as kem:
            shared_secret = kem.decap_secret(ciphertext)
        return shared_secret[:32]
    else:
        return ciphertext
