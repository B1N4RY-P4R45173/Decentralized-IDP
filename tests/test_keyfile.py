import os
import pytest
from crypto.keyfile import save_keyfile, load_keyfile
from crypto.pqc import generate_keypair, PQC_AVAILABLE


def _alg() -> str:
    return "ML-DSA-65" if PQC_AVAILABLE else "Ed25519"


def test_roundtrip(tmp_path):
    priv, pub = generate_keypair()
    path = str(tmp_path / "test.key")
    save_keyfile(priv, pub, "correctpassword", path, _alg())
    loaded_priv, loaded_pub = load_keyfile(path, "correctpassword")
    assert loaded_priv == priv
    assert loaded_pub == pub


def test_wrong_password(tmp_path):
    priv, pub = generate_keypair()
    path = str(tmp_path / "test.key")
    save_keyfile(priv, pub, "correctpassword", path, _alg())
    with pytest.raises(ValueError):
        load_keyfile(path, "wrongpassword")


def test_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_keyfile(str(tmp_path / "nonexistent.key"), "pass")


def test_public_key_preserved(tmp_path):
    priv, pub = generate_keypair()
    path = str(tmp_path / "test.key")
    save_keyfile(priv, pub, "pass", path, _alg())
    _, loaded_pub = load_keyfile(path, "pass")
    assert loaded_pub == pub


def test_different_passwords_different_files(tmp_path):
    priv, pub = generate_keypair()
    p1 = str(tmp_path / "k1.key")
    p2 = str(tmp_path / "k2.key")
    save_keyfile(priv, pub, "passA", p1, _alg())
    save_keyfile(priv, pub, "passB", p2, _alg())
    # ciphertexts differ even for same plaintext (random salt+nonce)
    import json
    with open(p1) as f:
        d1 = json.load(f)
    with open(p2) as f:
        d2 = json.load(f)
    assert d1["ciphertext"] != d2["ciphertext"]
    assert d1["salt"] != d2["salt"]
