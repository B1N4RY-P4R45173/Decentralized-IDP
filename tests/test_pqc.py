import pytest
from crypto.pqc import (
    PQC_AVAILABLE,
    generate_keypair,
    sign,
    verify,
    kem_generate_keypair,
    kem_encapsulate,
    kem_decapsulate,
)


def test_keypair_lengths():
    priv, pub = generate_keypair()
    if PQC_AVAILABLE:
        assert len(priv) == 4032
        assert len(pub) == 1952
    else:
        assert len(priv) == 32
        assert len(pub) == 32


def test_sign_and_verify():
    priv, pub = generate_keypair()
    msg = b"hello world"
    sig = sign(priv, msg)
    assert verify(pub, msg, sig)


def test_verify_wrong_message():
    priv, pub = generate_keypair()
    sig = sign(priv, b"correct")
    assert not verify(pub, b"wrong", sig)


def test_verify_bad_signature():
    _, pub = generate_keypair()
    assert not verify(pub, b"msg", b"badsig")


def test_verify_empty_signature():
    _, pub = generate_keypair()
    assert not verify(pub, b"msg", b"")


def test_kem_roundtrip():
    priv, pub = kem_generate_keypair()
    ct, ss_enc = kem_encapsulate(pub)
    ss_dec = kem_decapsulate(priv, ct)
    assert ss_enc == ss_dec
    assert len(ss_enc) == 32


@pytest.mark.skipif(not PQC_AVAILABLE, reason="liboqs not available")
def test_pqc_sign_size():
    priv, pub = generate_keypair()
    sig = sign(priv, b"test")
    assert len(sig) == 3309
