import secrets
import pytest
from crypto import THRESHOLD, N_NODES
from crypto.feldman import generate_commitments, verify_share
from crypto.sss import generate_shares


def _shares_and_commitments():
    S = secrets.randbelow(2**128) + 1
    shares = generate_shares(S, THRESHOLD, N_NODES)
    y_values = [s[1] for s in shares]
    commitments, salt = generate_commitments(y_values)
    return shares, commitments, salt


def test_commitments_count():
    shares, commitments, _ = _shares_and_commitments()
    assert len(commitments) == N_NODES


def test_all_shares_verify():
    shares, commitments, salt = _shares_and_commitments()
    for share in shares:
        assert verify_share(share, commitments, salt)


def test_tampered_y_fails():
    shares, commitments, salt = _shares_and_commitments()
    x, y = shares[0]
    assert not verify_share((x, y + 1), commitments, salt)


def test_wrong_node_fails():
    shares, commitments, salt = _shares_and_commitments()
    # share from node 1 checked against node 2's slot
    x1, y1 = shares[0]
    x2, y2 = shares[1]
    assert not verify_share((x2, y1), commitments, salt)


def test_salt_generates_fresh():
    values = [1, 2, 3]
    c1, s1 = generate_commitments(values)
    c2, s2 = generate_commitments(values)
    assert s1 != s2
    assert c1 != c2


def test_explicit_salt_deterministic():
    salt = secrets.token_bytes(32)
    c1, _ = generate_commitments([10, 20, 30], salt=salt)
    c2, _ = generate_commitments([10, 20, 30], salt=salt)
    assert c1 == c2
