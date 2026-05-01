"""
Password-protected keyfile for storing the user's private key locally.
Private key encrypted with AES-256-GCM; key derived via PBKDF2-HMAC-SHA3-256.

File format (JSON):
{
  "version": 1,
  "alg": "ML-DSA-65" | "Ed25519",
  "salt": "<hex>",        # 32 bytes, random
  "nonce": "<hex>",       # 12 bytes, random
  "ciphertext": "<hex>",  # AES-256-GCM encrypted private key
  "public_key": "<hex>"   # plaintext public key for reference
}
"""

import hashlib
import json
import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _derive_aes_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha3_256",
        password.encode("utf-8"),
        salt,
        iterations=600_000,
        dklen=32,
    )


def save_keyfile(
    private_key_bytes: bytes,
    public_key_bytes: bytes,
    password: str,
    path: str,
    alg: str,
) -> None:
    salt = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    aes_key = _derive_aes_key(password, salt)
    aes = AESGCM(aes_key)
    ciphertext = aes.encrypt(nonce, private_key_bytes, None)

    payload = {
        "version": 1,
        "alg": alg,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "public_key": public_key_bytes.hex(),
    }

    expanded = os.path.expanduser(path)
    os.makedirs(os.path.dirname(expanded) if os.path.dirname(expanded) else ".", exist_ok=True)
    with open(expanded, "w") as f:
        json.dump(payload, f)


def load_keyfile(path: str, password: str) -> tuple[bytes, bytes]:
    expanded = os.path.expanduser(path)
    if not os.path.exists(expanded):
        raise FileNotFoundError(f"Keyfile not found: {expanded}")

    with open(expanded) as f:
        payload = json.load(f)

    salt = bytes.fromhex(payload["salt"])
    nonce = bytes.fromhex(payload["nonce"])
    ciphertext = bytes.fromhex(payload["ciphertext"])
    public_key_bytes = bytes.fromhex(payload["public_key"])

    aes_key = _derive_aes_key(password, salt)
    aes = AESGCM(aes_key)
    try:
        private_key_bytes = aes.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Wrong password or corrupted keyfile")

    return private_key_bytes, public_key_bytes
