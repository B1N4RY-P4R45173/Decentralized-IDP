from crypto import P


def mod_inverse(a: int, p: int) -> int:
    if a == 0:
        raise ValueError("Cannot compute modular inverse of 0")
    return pow(a, p - 2, p)


def lagrange_interpolate(shares: list[tuple[int, int]], p: int = P) -> int:
    result = 0
    for i, (x_i, y_i) in enumerate(shares):
        basis = 1
        for j, (x_j, _) in enumerate(shares):
            if i != j:
                num = (-x_j) % p
                den = mod_inverse((x_i - x_j) % p, p)
                basis = (basis * num % p) * den % p
        result = (result + y_i * basis) % p
    return result
