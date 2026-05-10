"""
Four attack classes for the live demonstration.
Each has trigger() to activate and reset() to restore normal state.
"""

import hashlib

from crypto import P, THRESHOLD
from crypto.lagrange import lagrange_interpolate


class NodeCrashAttack:
    """
    Attack 1: Simulates Node going completely offline.
    Sets node.online = False.
    """

    def __init__(self, target_node_id: int, nodes: list):
        self.target_id = target_node_id
        self.node = next(n for n in nodes if n.node_id == target_node_id)

    def trigger(self):
        self.node.online = False
        print(f"\n\U0001f480 [ATTACK 1] Node {self.target_id} is now OFFLINE\n")

    def reset(self):
        self.node.online = True
        print(f"✅ [ATTACK 1] Node {self.target_id} restored ONLINE\n")


class ByzantineWrongProofAttack:
    """
    Attack 2: Node sends deliberately wrong partial proof.
    Sets node.byzantine = True.
    """

    def __init__(self, target_node_id: int, nodes: list):
        self.target_id = target_node_id
        self.node = next(n for n in nodes if n.node_id == target_node_id)

    def trigger(self):
        self.node.byzantine = True
        print(f"\n\U0001f534 [ATTACK 2] Node {self.target_id} is now BYZANTINE")
        print(f"   It will send WRONG partial proofs.\n")

    def reset(self):
        self.node.byzantine = False
        print(f"✅ [ATTACK 2] Node {self.target_id} restored to honest.\n")


class ShareTheftAttack:
    """
    Attack 3: Two compromised nodes pool their shares and attempt
    to reconstruct S using Lagrange interpolation.
    Demonstrates that t-1=2 shares are mathematically insufficient.
    """

    def __init__(
        self,
        attacker_node_ids: list[int],
        nodes: list,
        ledger,
    ):
        assert len(attacker_node_ids) == 2
        self.attacker_ids = attacker_node_ids
        self.nodes = {n.node_id: n for n in nodes}
        self.ledger = ledger

    def trigger(self, target_did: str) -> bool:
        print(
            f"\n\U0001f534 [ATTACK 3] Compromised nodes "
            f"{self.attacker_ids[0]} and {self.attacker_ids[1]} pooling shares..."
        )

        stolen_shares = []
        for node_id in self.attacker_ids:
            node = self.nodes[node_id]
            share = node.share_store.get_share(target_did)
            if share is None:
                print(f"   Node {node_id}: no share found for {target_did}")
                return False
            x, y = share
            print(f"   Node {node_id}: stole share x={x}, y={hex(y)[:18]}...")
            stolen_shares.append((x, y))

        print(
            f"   Attempting Lagrange interpolation with "
            f"{len(stolen_shares)} shares (need {THRESHOLD})..."
        )

        fake_S = lagrange_interpolate(stolen_shares, P)

        computed = hashlib.sha3_256(fake_S.to_bytes(32, "big")).hexdigest()
        stored = self.ledger.get_commitment_hash(target_did)

        fake_S = 0
        del fake_S

        if computed == stored:
            print(f"   ❌ CRITICAL: attack succeeded — this is a bug")
            return True
        else:
            print(f"   ✅ ATTACK FAILED — 2 shares reveal ZERO information about S")
            print(f"      Reconstructed hash: {computed[:32]}...")
            print(f"      Real commitment:    {stored[:32]}...")
            print(f"      These will NEVER match with fewer than t={THRESHOLD} shares.")
            return False


class ReplayAttack:
    """
    Attack 4: Intercepts a valid auth message and tries to reuse it.
    Demonstrates single-use challenge nonces.
    """

    def __init__(self, auth_service):
        self.auth_service = auth_service
        self._intercepted = None

    def intercept(self, did: str, challenge_id: str, signature_hex: str):
        self._intercepted = {
            "did": did,
            "challenge_id": challenge_id,
            "signature": signature_hex,
        }
        print(f"\n\U0001f534 [ATTACK 4] Intercepted auth message")
        print(f"   challenge_id: {challenge_id[:12]}...\n")

    def replay(self) -> dict:
        if self._intercepted is None:
            raise RuntimeError("Nothing intercepted yet — call intercept() first")

        result = self.auth_service.authenticate(
            self._intercepted["did"],
            self._intercepted["challenge_id"],
            self._intercepted["signature"],
        )

        if result["status"] == "failed":
            print(
                f"   ✅ REPLAY ATTACK FAILED — challenge nonce already consumed"
            )
        else:
            print(
                f"   ❌ REPLAY ATTACK SUCCEEDED — this is a bug"
            )

        return result
