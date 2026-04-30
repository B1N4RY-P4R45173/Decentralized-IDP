import hashlib
import hmac
from crypto import P


def derive_identity_secret(
    public_key_bytes: bytes,
    registration_nonce: bytes,
    password: str
) -> int:
    ikm = public_key_bytes + password.encode("utf-8")
    prk = hmac.new(key=registration_nonce, msg=ikm, digestmod=hashlib.sha3_256).digest()
    okm = hmac.new(
        key=prk,
        msg=b"decidp-identity-secret-v1" + b"\x01",
        digestmod=hashlib.sha3_256,
    ).digest()
    S = int.from_bytes(okm, "big") % (P - 1) + 1
    return S


def commitment_hash(S: int) -> str:
    return hashlib.sha3_256(S.to_bytes(32, "big")).hexdigest()
