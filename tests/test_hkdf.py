import hashlib
import secrets
from crypto import P
from crypto.hkdf import derive_identity_secret, commitment_hash


_PUB = b"\xab" * 32
_NONCE = secrets.token_bytes(32)


def test_deterministic():
    s1 = derive_identity_secret(_PUB, _NONCE, "password")
    s2 = derive_identity_secret(_PUB, _NONCE, "password")
    assert s1 == s2


def test_different_password():
    s1 = derive_identity_secret(_PUB, _NONCE, "passwordA")
    s2 = derive_identity_secret(_PUB, _NONCE, "passwordB")
    assert s1 != s2


def test_different_nonce():
    nonce2 = secrets.token_bytes(32)
    s1 = derive_identity_secret(_PUB, _NONCE, "password")
    s2 = derive_identity_secret(_PUB, nonce2, "password")
    assert s1 != s2


def test_s_in_range():
    s = derive_identity_secret(_PUB, _NONCE, "test")
    assert 1 <= s <= P - 1


def test_commitment_hash():
    s = derive_identity_secret(_PUB, _NONCE, "password")
    expected = hashlib.sha3_256(s.to_bytes(32, "big")).hexdigest()
    assert commitment_hash(s) == expected


def test_commitment_hash_length():
    s = derive_identity_secret(_PUB, _NONCE, "password")
    assert len(commitment_hash(s)) == 64
