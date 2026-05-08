"""Full authentication flow orchestrator (9-step)."""

import base64
import hashlib
import itertools
import json
from collections import Counter

from crypto import IAT_TTL_SECONDS, N_NODES, THRESHOLD
from crypto.pqc import verify as pqc_verify
from node.pbft import run_pbft_round
from node.partial_proof import recover_secret_from_partial_proofs
from authentication import iat


def _fail(reason: str) -> dict:
    return {"status": "failed", "reason": reason, "iat": None, "expires_in": None}


def _extract_jti(token: str) -> str | None:
    try:
        _, payload_b64, _ = token.split(".")
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        return payload.get("jti")
    except Exception:
        return None


class AuthenticationService:

    def __init__(
        self,
        nodes: list,
        ledger,
        challenge_manager,
        transport,
        data_dir: str = "data",
    ):
        self.nodes = nodes
        self.ledger = ledger
        self.challenge_manager = challenge_manager
        self.transport = transport
        self.data_dir = data_dir

    def authenticate(self, did: str, challenge_id: str, signature_hex: str) -> dict:
        # ── Step 1: consume challenge ─────────────────────────────────────
        nonce = self.challenge_manager.consume(challenge_id)
        if nonce is None:
            return _fail("challenge_expired_or_invalid")

        # ── Step 2: look up DID ───────────────────────────────────────────
        public_key_bytes = self.ledger.get_public_key(did)
        if public_key_bytes is None:
            return _fail("did_not_found")

        # ── Step 3: verify signature ──────────────────────────────────────
        try:
            signature_bytes = bytes.fromhex(signature_hex)
        except ValueError:
            self.ledger.append("AUTH_FAIL", did, {"reason": "invalid_signature"})
            return _fail("invalid_signature")

        signed_message = nonce + did.encode("utf-8")
        if not pqc_verify(public_key_bytes, signed_message, signature_bytes):
            self.ledger.append("AUTH_FAIL", did, {"reason": "invalid_signature"})
            return _fail("invalid_signature")

        # ── Step 4: collect partial proofs from all nodes ─────────────────
        proofs = []
        for node in self.nodes:
            proof = self.transport.request_partial_proof(
                node.node_id, did, nonce.hex()
            )
            status = "responded" if proof is not None else (
                "offline" if not node.online else "error"
            )
            print(f"  [Node {node.node_id}] {status}")
            if proof is not None:
                proofs.append(proof)

        # ── Step 5: PBFT consensus ────────────────────────────────────────
        round_id = hashlib.sha3_256(nonce + did.encode()).hexdigest()[:16]
        honest_proofs = run_pbft_round(round_id, proofs)
        if honest_proofs is None:
            self.ledger.append("AUTH_FAIL", did, {"reason": "quorum_not_reached"})
            return _fail("quorum_not_reached")

        # ── Steps 6+7: try all THRESHOLD-subsets of PBFT-clean proofs ─────
        # A Byzantine node may pass PBFT (correct challenge_hash/H but wrong
        # partial_value). We iterate all C(n_clean, THRESHOLD) combinations
        # until one reconstructs an S whose commitment hash matches the ledger.
        stored = self.ledger.get_commitment_hash(did)

        if proofs:
            maj_hash = Counter(
                p["challenge_hash"] for p in proofs
            ).most_common(1)[0][0]
            maj_h_candidates = [
                p for p in proofs if p["challenge_hash"] == maj_hash
            ]
            maj_H = Counter(
                p["H"] for p in maj_h_candidates
            ).most_common(1)[0][0]
            clean_proofs = [
                p for p in proofs
                if p["challenge_hash"] == maj_hash and p["H"] == maj_H
            ]
        else:
            clean_proofs = honest_proofs

        chosen = None
        S_reconstructed = None
        for subset in itertools.combinations(clean_proofs, THRESHOLD):
            S_try = recover_secret_from_partial_proofs(list(subset))
            computed = hashlib.sha3_256(
                S_try.to_bytes(32, "big")
            ).hexdigest()
            if computed == stored:
                chosen = list(subset)
                S_reconstructed = S_try
                break
            S_try = 0
            del S_try

        if chosen is None:
            self.ledger.append("AUTH_FAIL", did, {"reason": "commitment_mismatch"})
            return _fail("commitment_mismatch")

        # ── Step 8: zero S ────────────────────────────────────────────────
        S_reconstructed = 0
        del S_reconstructed

        # ── Step 9: issue IAT ─────────────────────────────────────────────
        quorum_nodes = [p["node_id"] for p in chosen]
        token = iat.issue(did, quorum_nodes)
        self.ledger.append("AUTH_SUCCESS", did, {
            "quorum_nodes": quorum_nodes,
            "token_jti": _extract_jti(token),
        })
        return {
            "status":     "success",
            "iat":        token,
            "expires_in": IAT_TTL_SECONDS,
        }
