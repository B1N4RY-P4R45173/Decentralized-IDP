"""
Identity Assertion Token (IAT).
Structured like a JWT but issued by the decentralised system.
Signed with the SYSTEM private key (ML-DSA-65 or Ed25519 fallback).
TTL: 60 seconds.
"""

import base64
import json
import os
import time
import uuid

from crypto import IAT_TTL_SECONDS
from crypto.pqc import PQC_AVAILABLE, generate_keypair
from crypto.pqc import sign as pqc_sign
from crypto.pqc import verify as pqc_verify

# System key pair — generated fresh at startup, persisted to data/system.key
_system_private_key: bytes | None = None
_system_public_key: bytes | None = None


def init_system_keys(data_dir: str = "data") -> None:
    """Load or generate the system signing key pair."""
    global _system_private_key, _system_public_key

    os.makedirs(data_dir, exist_ok=True)
    priv_path = os.path.join(data_dir, "system.key")
    pub_path = os.path.join(data_dir, "system.pub")

    if os.path.exists(priv_path) and os.path.exists(pub_path):
        with open(priv_path, "rb") as f:
            _system_private_key = f.read()
        with open(pub_path, "rb") as f:
            _system_public_key = f.read()
    else:
        priv, pub = generate_keypair()
        with open(priv_path, "wb") as f:
            f.write(priv)
        with open(pub_path, "wb") as f:
            f.write(pub)
        _system_private_key = priv
        _system_public_key = pub


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def issue(did: str, quorum_nodes: list[int]) -> str:
    if _system_private_key is None:
        raise RuntimeError("System keys not initialised — call init_system_keys() first")

    now = int(time.time())
    payload = {
        "sub":    did,
        "iat":    now,
        "exp":    now + IAT_TTL_SECONDS,
        "jti":    str(uuid.uuid4()),
        "quorum": sorted(quorum_nodes),
        "iss":    "did:decidp:system",
    }

    alg_name = "ML-DSA-65" if PQC_AVAILABLE else "Ed25519"
    header_b64 = _b64url_encode(
        json.dumps({"alg": alg_name, "typ": "DECIDP-IAT"}).encode()
    )
    payload_b64 = _b64url_encode(
        json.dumps(payload, sort_keys=True).encode()
    )
    signing_input = f"{header_b64}.{payload_b64}"
    sig = pqc_sign(_system_private_key, signing_input.encode())
    return f"{signing_input}.{_b64url_encode(sig)}"


def verify_iat(token: str) -> dict | None:
    """Return payload dict if token is valid and not expired; else None."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts

        signing_input = f"{header_b64}.{payload_b64}"
        sig = _b64url_decode(sig_b64)

        if _system_public_key is None:
            return None
        if not pqc_verify(_system_public_key, signing_input.encode(), sig):
            return None

        payload = json.loads(_b64url_decode(payload_b64))
        if time.time() > payload["exp"]:
            return None

        return payload
    except Exception:
        return None
