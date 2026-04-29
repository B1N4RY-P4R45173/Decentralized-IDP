import itertools
import secrets as _secrets
import pytest
from crypto import P, N_NODES, THRESHOLD
from crypto.sss import generate_shares, reconstruct_secret


def _make_shares(secret: int, t: int = THRESHOLD, n: int = N_NODES) -> list[tuple[int, int]]:
    return generate_shares(secret, t, n)


def test_reconstruct_all_combinations():
    secret = _secrets.randbelow(P - 1) + 1
    shares = _make_shares(secret)
    for subset in itertools.combinations(shares, THRESHOLD):
        assert reconstruct_secret(list(subset)) == secret


def test_two_shares_fail():
    secret = _secrets.randbelow(P - 1) + 1
    shares = _make_shares(secret)
    for subset in itertools.combinations(shares, THRESHOLD - 1):
        recovered = reconstruct_secret(list(subset))
        assert recovered != secret, f"2-share reconstruction should not equal secret"


def test_different_configs():
    # t=2, n=3
    s1 = _secrets.randbelow(P - 1) + 1
    shares = generate_shares(s1, t=2, n=3)
    assert len(shares) == 3
    assert reconstruct_secret(shares[:2]) == s1

    # t=4, n=7
    s2 = _secrets.randbelow(P - 1) + 1
    shares = generate_shares(s2, t=4, n=7)
    assert len(shares) == 7
    for subset in itertools.combinations(shares, 4):
        assert reconstruct_secret(list(subset)) == s2


def test_secret_range_min():
    shares = _make_shares(1)
    for subset in itertools.combinations(shares, THRESHOLD):
        assert reconstruct_secret(list(subset)) == 1


def test_secret_range_max():
    secret = P - 1
    shares = _make_shares(secret)
    for subset in itertools.combinations(shares, THRESHOLD):
        assert reconstruct_secret(list(subset)) == secret


def test_secret_range_random():
    secret = _secrets.randbelow(P - 1) + 1
    shares = _make_shares(secret)
    for subset in itertools.combinations(shares, THRESHOLD):
        assert reconstruct_secret(list(subset)) == secret


def test_invalid_secret_zero():
    with pytest.raises(ValueError):
        generate_shares(0, THRESHOLD, N_NODES)


def test_invalid_secret_too_large():
    with pytest.raises(ValueError):
        generate_shares(P, THRESHOLD, N_NODES)
