"""
Simplified 3-phase PBFT for 5 nodes (f=1).

No view changes or checkpointing — sufficient to demonstrate BFT for a
prototype. Full PBFT (Castro-Liskov 1999) with view changes is future work.
Nodes communicate via the transport layer; this module contains consensus
logic only.
"""

from collections import Counter

from crypto import N_NODES, THRESHOLD, F_NODES


class PBFTRound:
    """Represents one authentication consensus round."""

    def __init__(self, round_id: str, n: int = N_NODES, f: int = F_NODES):
        self.round_id = round_id
        self.n = n
        self.f = f
        self.quorum = 2 * f + 1   # = 3
        self.prepare_messages: list[dict] = []
        self.committed = False
        self.result: list[dict] | None = None

    def add_prepare_message(self, proof: dict) -> None:
        seen_ids = {p["node_id"] for p in self.prepare_messages}
        if proof["node_id"] not in seen_ids:
            self.prepare_messages.append(proof)

    def try_commit(self) -> list[dict] | None:
        if not self.prepare_messages:
            return None

        # Step 1 — find the majority challenge_hash
        hash_counts = Counter(p["challenge_hash"] for p in self.prepare_messages)
        majority_hash, _ = hash_counts.most_common(1)[0]

        # Step 2 — among majority-hash proofs, find the majority H
        # (catches a Byzantine node that has the correct challenge_hash but wrong H)
        candidates = [p for p in self.prepare_messages if p["challenge_hash"] == majority_hash]
        h_counts = Counter(p["H"] for p in candidates)
        majority_H, _ = h_counts.most_common(1)[0]

        # Step 3 — accept only proofs with majority challenge_hash AND majority H
        accepted = [p for p in candidates if p["H"] == majority_H]

        # Log every discarded proof
        accepted_ids = {p["node_id"] for p in accepted}
        for p in self.prepare_messages:
            if p["node_id"] not in accepted_ids:
                print(
                    f"[PBFT] Node {p['node_id']} proof DISCARDED: challenge_hash mismatch"
                )

        # Step 4 — commit if quorum reached
        if len(accepted) >= self.quorum:
            self.committed = True
            self.result = accepted
            return accepted[:THRESHOLD]

        return None

    @property
    def is_committed(self) -> bool:
        return self.committed


def run_pbft_round(
    round_id: str,
    partial_proofs: list[dict],
) -> list[dict] | None:
    """
    Run a complete PBFT round.
    Returns exactly THRESHOLD honest proofs on success, None on failure.
    """
    pbft = PBFTRound(round_id)
    for proof in partial_proofs:
        pbft.add_prepare_message(proof)
    return pbft.try_commit()
