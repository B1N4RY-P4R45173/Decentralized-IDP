import hashlib
import secrets

import pytest

from crypto import P, THRESHOLD, N_NODES
from node.pbft import PBFTRound, run_pbft_round


# ── proof factories ───────────────────────────────────────────────────────────

def _honest_proof(node_id: int, nonce: bytes) -> dict:
    challenge_hash = hashlib.sha3_256(nonce).hexdigest()
    H = int(challenge_hash, 16) % P
    # partial_value just needs to be a valid integer; math correctness
    # is tested in test_partial_proof.py, not here
    return {
        "node_id": node_id,
        "x": node_id,
        "partial_value": (node_id * 12345) % P,
        "H": H,
        "challenge_hash": challenge_hash,
    }


def _byzantine_proof(node_id: int) -> dict:
    """Wrong challenge — simulates a proof that references a different nonce."""
    bad_nonce = secrets.token_bytes(32)  # unique random wrong nonce
    challenge_hash = hashlib.sha3_256(bad_nonce).hexdigest()
    H = int(challenge_hash, 16) % P
    return {
        "node_id": node_id,
        "x": node_id,
        "partial_value": (node_id * 99999) % P,
        "H": H,
        "challenge_hash": challenge_hash,
    }


# ── required tests ────────────────────────────────────────────────────────────

def test_quorum_reached_4_honest():
    nonce = secrets.token_bytes(32)
    proofs = [_honest_proof(i, nonce) for i in range(1, 5)]  # nodes 1–4 honest
    proofs.append(_byzantine_proof(5))                        # node 5 byzantine

    result = run_pbft_round("round-1", proofs)

    assert result is not None
    assert len(result) == THRESHOLD
    returned_ids = {p["node_id"] for p in result}
    assert 5 not in returned_ids  # byzantine node excluded


def test_quorum_reached_3_honest():
    nonce = secrets.token_bytes(32)
    proofs = [_honest_proof(i, nonce) for i in range(1, 4)]  # nodes 1–3 honest
    proofs.append(_byzantine_proof(4))                        # each byzantine has
    proofs.append(_byzantine_proof(5))                        # a unique wrong hash

    result = run_pbft_round("round-2", proofs)

    assert result is not None
    assert len(result) == THRESHOLD
    returned_ids = {p["node_id"] for p in result}
    assert returned_ids.issubset({1, 2, 3})


def test_quorum_failed_2_honest():
    nonce = secrets.token_bytes(32)
    proofs = [_honest_proof(i, nonce) for i in range(1, 3)]  # only 2 honest
    for i in range(3, 6):                                      # 3 byzantine,
        proofs.append(_byzantine_proof(i))                     # each unique wrong hash

    result = run_pbft_round("round-3", proofs)

    assert result is None


def test_byzantine_detection(capsys):
    nonce = secrets.token_bytes(32)
    proofs = [_honest_proof(i, nonce) for i in range(1, 5)]
    proofs.append(_byzantine_proof(5))

    result = run_pbft_round("round-4", proofs)

    assert result is not None
    # Byzantine node must NOT appear in the committed proofs
    assert all(p["node_id"] != 5 for p in result)
    # PBFT must have logged the discard
    captured = capsys.readouterr()
    assert "Node 5" in captured.out
    assert "DISCARDED" in captured.out


# ── additional coverage ───────────────────────────────────────────────────────

def test_empty_round_returns_none():
    assert run_pbft_round("empty", []) is None


def test_duplicate_node_id_ignored():
    nonce = secrets.token_bytes(32)
    # Same node_id submitted twice — second must be ignored
    proofs = [_honest_proof(1, nonce)] * 2
    proofs += [_honest_proof(i, nonce) for i in range(2, 5)]

    pbft = PBFTRound("dup-test")
    for p in proofs:
        pbft.add_prepare_message(p)
    # node 1 must appear exactly once
    assert sum(1 for p in pbft.prepare_messages if p["node_id"] == 1) == 1


def test_is_committed_property():
    nonce = secrets.token_bytes(32)
    proofs = [_honest_proof(i, nonce) for i in range(1, 4)]
    pbft = PBFTRound("prop-test")
    for p in proofs:
        pbft.add_prepare_message(p)
    assert not pbft.is_committed
    pbft.try_commit()
    assert pbft.is_committed


def test_result_exactly_threshold_proofs():
    nonce = secrets.token_bytes(32)
    proofs = [_honest_proof(i, nonce) for i in range(1, N_NODES + 1)]
    result = run_pbft_round("threshold-test", proofs)
    assert result is not None
    assert len(result) == THRESHOLD


def test_byzantine_with_correct_hash_wrong_H():
    """Node has matching challenge_hash but forged H — must be discarded."""
    nonce = secrets.token_bytes(32)
    proofs = [_honest_proof(i, nonce) for i in range(1, 4)]

    # Craft a proof with correct challenge_hash but wrong H
    correct_hash = hashlib.sha3_256(nonce).hexdigest()
    forged_H = 42  # definitely not int(correct_hash,16) % P
    forged = {
        "node_id": 5,
        "x": 5,
        "partial_value": 999,
        "H": forged_H,
        "challenge_hash": correct_hash,
    }
    proofs.append(forged)

    result = run_pbft_round("forged-H-test", proofs)
    assert result is not None
    assert all(p["node_id"] != 5 for p in result)
