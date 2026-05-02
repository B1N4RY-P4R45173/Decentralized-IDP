import json
import pytest
from ledger.ledger import Ledger


@pytest.fixture
def ledger(tmp_path):
    return Ledger(db_path=str(tmp_path / "ledger.db"))


# ── helpers ───────────────────────────────────────────────────────────────────

_DID = "did:decidp:abc123"

_REG_DATA = {
    "public_key": "deadbeef" * 8,
    "commitment_hash": "cafebabe" * 8,
    "nonce": "11223344" * 8,
    "feldman_commitments": ["aabbccdd" * 8, "eeff0011" * 8, "22334455" * 8],
    "feldman_salt": "55667788" * 8,
    "registered_at": 1700000000,
}


# ── required tests ────────────────────────────────────────────────────────────

def test_chain_valid(ledger):
    for i in range(5):
        ledger.append("AUTH_SUCCESS", f"did:decidp:user{i}", {"info": i})
    assert ledger.verify_chain() is True


def test_chain_tampered(ledger):
    for i in range(5):
        ledger.append("AUTH_SUCCESS", f"did:decidp:user{i}", {"info": i})

    # Directly modify entry 2's data_json to simulate tampering
    ledger.conn.execute(
        "UPDATE entries SET data_json = ? WHERE id = 2",
        (json.dumps({"info": 999}),),
    )
    ledger.conn.commit()

    assert ledger.verify_chain() is False


def test_get_commitment_hash(ledger):
    ledger.append("DID_REGISTER", _DID, _REG_DATA)
    assert ledger.get_commitment_hash(_DID) == _REG_DATA["commitment_hash"]


def test_get_public_key(ledger):
    ledger.append("DID_REGISTER", _DID, _REG_DATA)
    assert ledger.get_public_key(_DID) == bytes.fromhex(_REG_DATA["public_key"])


# ── additional coverage ───────────────────────────────────────────────────────

def test_get_registration_nonce(ledger):
    ledger.append("DID_REGISTER", _DID, _REG_DATA)
    assert ledger.get_registration_nonce(_DID) == bytes.fromhex(_REG_DATA["nonce"])


def test_get_feldman_commitments(ledger):
    ledger.append("DID_REGISTER", _DID, _REG_DATA)
    result = ledger.get_feldman_commitments(_DID)
    assert result == [bytes.fromhex(c) for c in _REG_DATA["feldman_commitments"]]


def test_get_did_document(ledger):
    ledger.append("DID_REGISTER", _DID, _REG_DATA)
    doc = ledger.get_did_document(_DID)
    assert doc["commitment_hash"] == _REG_DATA["commitment_hash"]


def test_lookup_missing_did_returns_none(ledger):
    assert ledger.get_public_key("did:decidp:nobody") is None
    assert ledger.get_commitment_hash("did:decidp:nobody") is None
    assert ledger.get_registration_nonce("did:decidp:nobody") is None
    assert ledger.get_feldman_commitments("did:decidp:nobody") is None


def test_empty_chain_is_valid(ledger):
    assert ledger.verify_chain() is True


def test_append_returns_hash(ledger):
    h = ledger.append("AUTH_SUCCESS", _DID, {"ok": True})
    assert isinstance(h, str) and len(h) == 64


def test_get_all_entries(ledger):
    ledger.append("DID_REGISTER", _DID, _REG_DATA)
    ledger.append("AUTH_SUCCESS", _DID, {"quorum_nodes": [1, 2, 3]})
    entries = ledger.get_all_entries()
    assert len(entries) == 2
    assert entries[0]["entry_type"] == "DID_REGISTER"
    assert entries[1]["entry_type"] == "AUTH_SUCCESS"


def test_chain_tampered_previous_hash(ledger):
    for i in range(3):
        ledger.append("AUTH_SUCCESS", _DID, {"i": i})

    # Corrupt the previous_hash pointer of entry 3
    ledger.conn.execute(
        "UPDATE entries SET previous_hash = ? WHERE id = 3",
        ("0" * 64,),
    )
    ledger.conn.commit()

    assert ledger.verify_chain() is False
