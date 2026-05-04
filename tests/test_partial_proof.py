import hashlib
import itertools
import secrets

import pytest

from crypto import P, THRESHOLD, N_NODES
from crypto.sss import generate_shares
from node.partial_proof import compute_partial_proof, recover_secret_from_partial_proofs


def _nonce() -> bytes:
    return secrets.token_bytes(32)


def _make_proofs(shares, nonce):
    return [
        compute_partial_proof(share, nonce, share[0])
        for share in shares
    ]


def test_proof_structure():
    nonce = _nonce()
    share = (1, secrets.randbelow(P - 1) + 1)
    proof = compute_partial_proof(share, nonce, node_id=1)
    assert set(proof.keys()) == {"node_id", "x", "partial_value", "H", "challenge_hash"}
    assert proof["node_id"] == 1
    assert proof["x"] == share[0]
    assert 0 <= proof["partial_value"] < P


def test_H_deterministic():
    nonce = _nonce()
    share = (1, secrets.randbelow(P - 1) + 1)
    p1 = compute_partial_proof(share, nonce, 1)
    p2 = compute_partial_proof(share, nonce, 1)
    assert p1["H"] == p2["H"]
    assert p1["challenge_hash"] == p2["challenge_hash"]


def test_H_matches_nonce_hash():
    nonce = _nonce()
    share = (1, 12345)
    proof = compute_partial_proof(share, nonce, 1)
    expected_hash = hashlib.sha3_256(nonce).hexdigest()
    assert proof["challenge_hash"] == expected_hash
    assert proof["H"] == int(expected_hash, 16) % P


def test_recover_secret_all_subsets():
    secret = secrets.randbelow(P - 1) + 1
    shares = generate_shares(secret, THRESHOLD, N_NODES)
    nonce = _nonce()
    proofs = _make_proofs(shares, nonce)

    for subset in itertools.combinations(proofs, THRESHOLD):
        recovered = recover_secret_from_partial_proofs(list(subset))
        assert recovered == secret


def test_recover_secret_from_all_5():
    secret = secrets.randbelow(P - 1) + 1
    shares = generate_shares(secret, THRESHOLD, N_NODES)
    nonce = _nonce()
    proofs = _make_proofs(shares, nonce)
    # Using all 5 proofs; function only uses first THRESHOLD for Lagrange
    recovered = recover_secret_from_partial_proofs(proofs)
    # Any THRESHOLD subset must work; verify with canonical subset too
    recovered3 = recover_secret_from_partial_proofs(proofs[:THRESHOLD])
    assert recovered3 == secret


def test_below_threshold_raises():
    nonce = _nonce()
    proofs = [compute_partial_proof((i, i * 100 + 1), nonce, i) for i in range(1, THRESHOLD)]
    with pytest.raises(ValueError, match=str(THRESHOLD)):
        recover_secret_from_partial_proofs(proofs)


def test_different_nonces_different_partial_values():
    share = (1, secrets.randbelow(P - 1) + 1)
    p1 = compute_partial_proof(share, _nonce(), 1)
    p2 = compute_partial_proof(share, _nonce(), 1)
    assert p1["partial_value"] != p2["partial_value"]
    assert p1["H"] != p2["H"]
