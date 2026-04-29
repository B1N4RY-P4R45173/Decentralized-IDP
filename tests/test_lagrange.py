import pytest
from crypto import P
from crypto.lagrange import mod_inverse, lagrange_interpolate


def test_interpolate_known():
    # f(x) = 7 + 3x + 2x^2  =>  f(0) = 7
    # f(1) = 7+3+2 = 12, f(2) = 7+6+8 = 21, f(3) = 7+9+18 = 34
    shares = [(1, 12), (2, 21), (3, 34)]
    assert lagrange_interpolate(shares) == 7


def test_interpolate_modular():
    # Same polynomial but values taken mod P — should still recover f(0)=7
    shares = [(1, 12 % P), (2, 21 % P), (3, 34 % P)]
    assert lagrange_interpolate(shares, P) == 7


def test_mod_inverse_correctness():
    for a in [2, 3, 7, 100, 99999, P - 1]:
        inv = mod_inverse(a, P)
        assert (a * inv) % P == 1


def test_mod_inverse_zero_raises():
    with pytest.raises(ValueError):
        mod_inverse(0, P)


def test_single_point():
    # f(x) = constant c  =>  f(0) = c  from any single share (x, c)
    assert lagrange_interpolate([(5, 42)]) == 42
