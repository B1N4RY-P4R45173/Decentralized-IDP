import hashlib

from crypto import P, THRESHOLD
from crypto.lagrange import lagrange_interpolate


def compute_partial_proof(
    share: tuple[int, int],
    challenge_nonce: bytes,
    node_id: int,
    p: int = P,
) -> dict:
    challenge_hash = hashlib.sha3_256(challenge_nonce).hexdigest()
    H = int(challenge_hash, 16) % p
    partial_value = (share[1] * H) % p
    return {
        "node_id": node_id,
        "x": share[0],
        "partial_value": partial_value,
        "H": H,
        "challenge_hash": challenge_hash,
    }


def recover_secret_from_partial_proofs(
    proofs: list[dict],
    p: int = P,
) -> int:
    if len(proofs) < THRESHOLD:
        raise ValueError(
            f"Need at least {THRESHOLD} partial proofs to reconstruct secret, got {len(proofs)}"
        )

    H = proofs[0]["H"]
    H_inv = pow(H, p - 2, p)

    recovered_shares = [
        (proof["x"], proof["partial_value"] * H_inv % p)
        for proof in proofs
    ]

    return lagrange_interpolate(recovered_shares, p)
