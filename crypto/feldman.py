"""
SHA-3 hash commitments instead of classic g^x mod p Feldman VSS.
Discrete-log commitments are broken by Shor's algorithm; this scheme
is PQC-safe. Documented as a deliberate design choice.

generate_commitments() is called with the share y-values [y_1..y_n],
one entry per node. verify_share() lets each node confirm its own
y-value matches the published commitment for that node index.
"""

import hashlib
import os
from crypto import P


def generate_commitments(
    coefficients: list[int],
    salt: bytes | None = None,
) -> tuple[list[bytes], bytes]:
    if salt is None:
        salt = os.urandom(32)

    commitments = []
    for i, value in enumerate(coefficients):
        h = hashlib.sha3_256()
        h.update(salt)
        h.update(i.to_bytes(4, "big"))
        h.update(value.to_bytes(32, "big"))
        commitments.append(h.digest())

    return commitments, salt


def verify_share(
    share: tuple[int, int],
    commitments: list[bytes],
    salt: bytes,
    p: int = P,
) -> bool:
    x, y = share
    idx = x - 1  # x is 1-based node_id; commitment list is 0-based
    if idx < 0 or idx >= len(commitments):
        return False

    h = hashlib.sha3_256()
    h.update(salt)
    h.update(idx.to_bytes(4, "big"))
    h.update(y.to_bytes(32, "big"))

    return h.digest() == commitments[idx]
