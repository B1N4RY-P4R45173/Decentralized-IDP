"""End-to-end integration test: register → challenge → sign → authenticate → verify IAT."""

import authentication.iat as _iat
from crypto.keyfile import load_keyfile
from crypto.pqc import sign as pqc_sign


_PASSWORD = "FullFlow@2026"


def test_end_to_end(registration_service, authentication_service, challenge_manager):
    # ── Register ──────────────────────────────────────────────────────────────
    result = registration_service.register(_PASSWORD)

    assert result["status"] == "success"
    did = result["did"]
    assert did.startswith("did:decidp:")
    keyfile_path = result["keyfile_path"]

    # ── Load private key ──────────────────────────────────────────────────────
    priv, _ = load_keyfile(keyfile_path, _PASSWORD)

    # ── Issue challenge ───────────────────────────────────────────────────────
    ch = challenge_manager.issue(did)
    assert "challenge_id" in ch
    assert "nonce" in ch
    assert ch["expires_in"] > 0

    # ── Sign challenge ────────────────────────────────────────────────────────
    nonce_bytes = bytes.fromhex(ch["nonce"])
    sig = pqc_sign(priv, nonce_bytes + did.encode("utf-8"))
    sig_hex = sig.hex()

    # ── Authenticate ──────────────────────────────────────────────────────────
    auth = authentication_service.authenticate(did, ch["challenge_id"], sig_hex)

    assert auth["status"] == "success"
    assert auth["iat"] is not None
    assert auth["expires_in"] is not None and auth["expires_in"] > 0

    # ── Verify IAT ───────────────────────────────────────────────────────────
    payload = _iat.verify_iat(auth["iat"])

    assert payload is not None
    assert payload["sub"] == did
    assert payload["iss"] == "did:decidp:system"
    assert "exp" in payload
    assert "jti" in payload
    assert "quorum" in payload
    assert len(payload["quorum"]) >= 3
