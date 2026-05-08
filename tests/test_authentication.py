"""Tests for authentication flow, IAT issuance, and edge cases."""

import time
from unittest.mock import patch

import pytest

import authentication.iat as _iat
from crypto import CHALLENGE_TTL_SECONDS, IAT_TTL_SECONDS
from crypto.keyfile import load_keyfile
from crypto.pqc import sign as pqc_sign

_PASSWORD = "AuthTest@2026"


# ── helper ─────────────────────────────────────────────────────────────────────

def _register_and_load_key(reg_service, password=_PASSWORD):
    """Register a user and return (result_dict, priv_key_bytes)."""
    result = reg_service.register(password)
    priv, _ = load_keyfile(result["keyfile_path"], password)
    return result, priv


def _sign_challenge(priv: bytes, nonce_hex: str, did: str) -> str:
    nonce_bytes = bytes.fromhex(nonce_hex)
    sig = pqc_sign(priv, nonce_bytes + did.encode("utf-8"))
    return sig.hex()


# ── required tests ─────────────────────────────────────────────────────────────

def test_auth_success(registration_service, authentication_service, challenge_manager):
    result, priv = _register_and_load_key(registration_service)
    did = result["did"]

    ch = challenge_manager.issue(did)
    sig_hex = _sign_challenge(priv, ch["nonce"], did)

    auth = authentication_service.authenticate(did, ch["challenge_id"], sig_hex)
    assert auth["status"] == "success"
    assert auth["iat"] is not None
    assert auth["expires_in"] == IAT_TTL_SECONDS


def test_auth_wrong_signature(registration_service, authentication_service, challenge_manager):
    result, _ = _register_and_load_key(registration_service)
    did = result["did"]

    ch = challenge_manager.issue(did)
    # sign something completely different
    _, other_priv = _register_and_load_key(registration_service, "OtherPass@1")
    sig_hex = _sign_challenge(other_priv, ch["nonce"], did)

    auth = authentication_service.authenticate(did, ch["challenge_id"], sig_hex)
    assert auth["status"] == "failed"
    assert auth["reason"] == "invalid_signature"


def test_auth_expired_challenge(registration_service, authentication_service, challenge_manager):
    result, priv = _register_and_load_key(registration_service)
    did = result["did"]

    ch = challenge_manager.issue(did)
    sig_hex = _sign_challenge(priv, ch["nonce"], did)

    # Advance time past CHALLENGE_TTL_SECONDS
    future = time.time() + CHALLENGE_TTL_SECONDS + 5
    with patch("time.time", return_value=future):
        auth = authentication_service.authenticate(did, ch["challenge_id"], sig_hex)

    assert auth["status"] == "failed"
    assert auth["reason"] == "challenge_expired_or_invalid"


def test_auth_wrong_did(authentication_service, challenge_manager):
    fake_did = "did:decidp:doesnotexist00"
    ch = challenge_manager.issue(fake_did)
    auth = authentication_service.authenticate(
        fake_did, ch["challenge_id"], "deadbeef"
    )
    assert auth["status"] == "failed"
    assert auth["reason"] == "did_not_found"


def test_iat_verify(registration_service, authentication_service, challenge_manager):
    result, priv = _register_and_load_key(registration_service)
    did = result["did"]

    ch = challenge_manager.issue(did)
    sig_hex = _sign_challenge(priv, ch["nonce"], did)
    auth = authentication_service.authenticate(did, ch["challenge_id"], sig_hex)

    payload = _iat.verify_iat(auth["iat"])
    assert payload is not None
    assert payload["sub"] == did
    assert payload["iss"] == "did:decidp:system"
    assert "exp" in payload and "jti" in payload


def test_iat_expired(tmp_path):
    _iat.init_system_keys(str(tmp_path))
    token = _iat.issue("did:decidp:test0001", [1, 2, 3])

    # Before expiry: valid
    assert _iat.verify_iat(token) is not None

    # After expiry: None
    future = time.time() + IAT_TTL_SECONDS + 5
    with patch("time.time", return_value=future):
        assert _iat.verify_iat(token) is None


# ── additional coverage ────────────────────────────────────────────────────────

def test_challenge_single_use(registration_service, authentication_service, challenge_manager):
    result, priv = _register_and_load_key(registration_service)
    did = result["did"]

    ch = challenge_manager.issue(did)
    sig_hex = _sign_challenge(priv, ch["nonce"], did)

    # First use succeeds
    auth1 = authentication_service.authenticate(did, ch["challenge_id"], sig_hex)
    assert auth1["status"] == "success"

    # Replay with same challenge_id fails
    auth2 = authentication_service.authenticate(did, ch["challenge_id"], sig_hex)
    assert auth2["status"] == "failed"
    assert auth2["reason"] == "challenge_expired_or_invalid"


def test_auth_ledger_records_success(registration_service, authentication_service, challenge_manager, ledger):
    result, priv = _register_and_load_key(registration_service)
    did = result["did"]

    ch = challenge_manager.issue(did)
    sig_hex = _sign_challenge(priv, ch["nonce"], did)
    authentication_service.authenticate(did, ch["challenge_id"], sig_hex)

    entries = ledger.get_all_entries()
    types = [e["entry_type"] for e in entries]
    assert "DID_REGISTER" in types
    assert "AUTH_SUCCESS" in types


def test_auth_ledger_records_failure(registration_service, authentication_service, challenge_manager, ledger):
    result, _ = _register_and_load_key(registration_service)
    did = result["did"]

    ch = challenge_manager.issue(did)
    authentication_service.authenticate(did, ch["challenge_id"], "badhex")

    entries = ledger.get_all_entries()
    assert any(e["entry_type"] == "AUTH_FAIL" for e in entries)


def test_iat_bad_signature(tmp_path):
    _iat.init_system_keys(str(tmp_path))
    token = _iat.issue("did:test:x", [1, 2, 3])
    parts = token.split(".")
    # Corrupt the signature
    corrupted = f"{parts[0]}.{parts[1]}.AAAAAAAAAA"
    assert _iat.verify_iat(corrupted) is None


def test_iat_malformed_token(tmp_path):
    _iat.init_system_keys(str(tmp_path))
    assert _iat.verify_iat("notavalidtoken") is None
    assert _iat.verify_iat("a.b") is None
    assert _iat.verify_iat("") is None


def test_auth_quorum_nodes_in_ledger(registration_service, authentication_service, challenge_manager, ledger):
    result, priv = _register_and_load_key(registration_service)
    did = result["did"]

    ch = challenge_manager.issue(did)
    sig_hex = _sign_challenge(priv, ch["nonce"], did)
    authentication_service.authenticate(did, ch["challenge_id"], sig_hex)

    entries = ledger.get_all_entries()
    success_entries = [e for e in entries if e["entry_type"] == "AUTH_SUCCESS"]
    assert len(success_entries) == 1
    assert "quorum_nodes" in success_entries[0]["data"]
    assert len(success_entries[0]["data"]["quorum_nodes"]) >= 3
