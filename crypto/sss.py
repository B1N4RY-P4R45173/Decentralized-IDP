import secrets
from crypto import P


def generate_shares(secret: int, t: int, n: int, p: int = P) -> list[tuple[int, int]]:
    if not (1 <= secret <= p - 1):
        raise ValueError(f"secret must be in [1, p-1]")
    if t < 1 or t > n:
        raise ValueError(f"threshold t must satisfy 1 <= t <= n")

    coeffs = [secret] + [secrets.randbelow(p - 1) + 1 for _ in range(t - 1)]

    shares = []
    for i in range(1, n + 1):
        y = 0
        for exp, coeff in enumerate(coeffs):
            y = (y + coeff * pow(i, exp, p)) % p
        shares.append((i, y))

    for i in range(len(coeffs)):
        coeffs[i] = 0

    return shares


def reconstruct_secret(shares: list[tuple[int, int]], p: int = P) -> int:
    from crypto.lagrange import lagrange_interpolate
    return lagrange_interpolate(shares, p)
