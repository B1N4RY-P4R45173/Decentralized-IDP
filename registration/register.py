"""Full registration flow orchestrator (12-step)."""

import hashlib
import secrets
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto import P, THRESHOLD, N_NODES
from crypto.feldman import generate_commitments
from crypto.hkdf import derive_identity_secret
from crypto.keyfile import save_keyfile
from crypto.pqc import generate_keypair, kem_encapsulate, PQC_AVAILABLE
from crypto.sss import generate_shares


class RegistrationService:

    def __init__(self, nodes: list, ledger, data_dir: str = "data"):
        self.nodes = nodes      # list of Node objects; index 0 → node_id 1
        self.ledger = ledger
        self.data_dir = data_dir

    def register(self, password: str) -> dict:
        # ── Step 1: generate key pair ─────────────────────────────────────
        priv, pub = generate_keypair()

        # ── Step 2: derive DID ────────────────────────────────────────────
        did = "did:decidp:" + hashlib.sha3_256(pub).hexdigest()[:16]

        # ── Step 3: registration nonce ────────────────────────────────────
        registration_nonce = secrets.token_bytes(32)

        # ── Step 4: derive identity secret S ─────────────────────────────
        S = derive_identity_secret(pub, registration_nonce, password)

        # ── Step 5: validate S ────────────────────────────────────────────
        assert 1 <= S <= P - 1, "HKDF produced out-of-range S"

        # ── Step 6: SSS shares ────────────────────────────────────────────
        shares = generate_shares(S, THRESHOLD, N_NODES)

        # ── Step 7: Feldman commitments (one per share y-value) ───────────
        y_values = [s[1] for s in shares]
        commitments, salt = generate_commitments(y_values)

        # ── Step 8: distribute shares to nodes ───────────────────────────
        for i, node in enumerate(self.nodes, start=1):
            share = shares[i - 1]           # (i, f(i))

            # 8b-d: KEM-encrypt y for the node (used in HTTP transport mode)
            node_kem_pub = node.kem_public_key
            _kem_ciphertext, shared_secret = kem_encapsulate(node_kem_pub)
            aes = AESGCM(shared_secret)
            _aes_nonce = secrets.token_bytes(12)
            _encrypted_y = aes.encrypt(
                _aes_nonce, share[1].to_bytes(32, "big"), did.encode()
            )
            # 8e: in LocalTransport mode store directly
            node.share_store.store_share(
                did, share[0], share[1],
                feldman_commitment=commitments[i - 1],
            )

        # ── Step 9: ledger entry ──────────────────────────────────────────
        commitment_hash = hashlib.sha3_256(S.to_bytes(32, "big")).hexdigest()
        self.ledger.append("DID_REGISTER", did, {
            "public_key":          pub.hex(),
            "commitment_hash":     commitment_hash,
            "nonce":               registration_nonce.hex(),
            "feldman_commitments": [c.hex() for c in commitments],
            "feldman_salt":        salt.hex(),
            "registered_at":       time.time(),
        })

        # ── Step 10: zero S and shares from memory ────────────────────────
        # Best-effort — Python GC is not guaranteed; documented limitation.
        S = 0
        for idx in range(len(shares)):
            shares[idx] = (0, 0)
        del S, shares

        # ── Step 11: save encrypted keyfile ──────────────────────────────
        alg = "ML-DSA-65" if PQC_AVAILABLE else "Ed25519"
        keyfile_path = f"~/.decidp/{did}.key"
        save_keyfile(priv, pub, password, path=keyfile_path, alg=alg)

        # ── Step 12: return (no private key) ─────────────────────────────
        return {
            "status":       "success",
            "did":          did,
            "public_key":   pub.hex(),
            "keyfile_path": keyfile_path,
            "message":      "Private key saved to keyfile. Keep your password safe.",
        }
