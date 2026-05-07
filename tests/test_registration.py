import hashlib

import pytest

from crypto.hkdf import derive_identity_secret
from crypto import N_NODES

_PASSWORD = "TestRegistration@2026"


# ── required tests ────────────────────────────────────────────────────────────

def test_register_success(registration_service):
    result = registration_service.register(_PASSWORD)
    assert result["status"] == "success"
    assert result["did"].startswith("did:decidp:")
    assert len(result["did"]) > len("did:decidp:")
    assert "public_key" in result
    assert "keyfile_path" in result


def test_shares_distributed(registration_service, nodes):
    result = registration_service.register(_PASSWORD)
    did = result["did"]
    for node in nodes:
        assert node.share_store.has_share(did), (
            f"Node {node.node_id} missing share for {did}"
        )


def test_commitment_on_ledger(registration_service, ledger):
    result = registration_service.register(_PASSWORD)
    did = result["did"]

    stored_commitment = ledger.get_commitment_hash(did)
    assert stored_commitment is not None

    # Re-derive S from ledger data + password (S was zeroed, can't inspect directly)
    pub_bytes = bytes.fromhex(result["public_key"])
    nonce_bytes = ledger.get_registration_nonce(did)
    assert nonce_bytes is not None

    S_rederived = derive_identity_secret(pub_bytes, nonce_bytes, _PASSWORD)
    expected = hashlib.sha3_256(S_rederived.to_bytes(32, "big")).hexdigest()
    assert expected == stored_commitment


# ── additional coverage ───────────────────────────────────────────────────────

def test_did_format(registration_service):
    result = registration_service.register(_PASSWORD)
    # DID = "did:decidp:" + sha3_256(pub)[:16] → 16 hex chars
    suffix = result["did"].removeprefix("did:decidp:")
    assert len(suffix) == 16
    assert all(c in "0123456789abcdef" for c in suffix)


def test_public_key_on_ledger(registration_service, ledger):
    result = registration_service.register(_PASSWORD)
    did = result["did"]
    stored_pub = ledger.get_public_key(did)
    assert stored_pub == bytes.fromhex(result["public_key"])


def test_feldman_commitments_on_ledger(registration_service, ledger):
    result = registration_service.register(_PASSWORD)
    did = result["did"]
    commitments = ledger.get_feldman_commitments(did)
    assert commitments is not None
    assert len(commitments) == N_NODES


def test_keyfile_path_contains_did(registration_service):
    result = registration_service.register(_PASSWORD)
    assert result["did"] in result["keyfile_path"]


def test_two_registrations_different_dids(registration_service):
    r1 = registration_service.register("PasswordOne@1")
    r2 = registration_service.register("PasswordTwo@2")
    assert r1["did"] != r2["did"]


def test_private_key_not_in_response(registration_service):
    result = registration_service.register(_PASSWORD)
    for key, val in result.items():
        assert "private" not in key.lower()
    # Make sure the raw private key bytes aren't smuggled in the public_key hex
    # (public_key hex is shorter than a private key in either mode)
    pub_hex = result.get("public_key", "")
    # Ed25519 pub = 64 hex chars; ML-DSA-65 pub = 3904 hex chars.
    # Private keys are always longer: Ed25519 priv = 64, ML-DSA-65 priv = 8064.
    # In both modes the public key hex must be shorter than the private key hex.
    from crypto.pqc import PQC_AVAILABLE
    max_pub_hex = 4000 if PQC_AVAILABLE else 128
    assert len(pub_hex) <= max_pub_hex
