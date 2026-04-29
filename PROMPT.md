Build a Decentralised Identity Provider (IDP) for Zero Trust Network Access (ZTNA)
using Shamir's Secret Sharing (SSS) and Byzantine Fault Tolerant (BFT) consensus,
with post-quantum cryptography (PQC) via liboqs.

════════════════════════════════════════════════════════════════
ENVIRONMENT FACTS — READ BEFORE WRITING ANY CODE
════════════════════════════════════════════════════════════════

- Python 3.12.3
- WSL2 Ubuntu on Windows with Docker Desktop
- Docker base image: openquantumsafe/liboqs-python:latest
  (this image has liboqs C library pre-built — DO NOT try to build
   liboqs from source anywhere in the codebase)
- liboqs-python 0.14.1 is the only version available on PyPI
- PQC algorithm name strings (EXACT, case-sensitive):
    Signatures : "ML-DSA-65"   (192-bit PQ security, replaces Ed25519)
    KEM        : "ML-KEM-768"  (192-bit PQ security, replaces ECDH)
  Use these exact strings in every oqs.Signature() and
  oqs.KeyEncapsulation() call. No other strings.
- All non-PQC code (SSS, PBFT, ledger, API) works in plain Python
  without Docker. The Dockerfile is only needed for PQC operations.
- GitHub Actions CI uses ubuntu-latest runner.

════════════════════════════════════════════════════════════════
PROJECT STRUCTURE — CREATE EXACTLY THIS
════════════════════════════════════════════════════════════════

decentralised-idp/
├── crypto/
│   ├── __init__.py
│   ├── sss.py
│   ├── lagrange.py
│   ├── feldman.py
│   ├── hkdf.py
│   ├── pqc.py              # liboqs wrapper (ML-DSA-65 + ML-KEM-768)
│   └── keyfile.py          # password-protected keyfile encrypt/decrypt
├── node/
│   ├── __init__.py
│   ├── node.py
│   ├── share_store.py
│   ├── partial_proof.py
│   ├── pbft.py
│   └── transport.py        # LocalTransport + HTTPTransport abstraction
├── registration/
│   ├── __init__.py
│   └── register.py
├── authentication/
│   ├── __init__.py
│   ├── authenticate.py
│   ├── challenge.py
│   └── iat.py
├── ledger/
│   ├── __init__.py
│   └── ledger.py
├── api/
│   ├── __init__.py
│   └── main.py
├── simulate/
│   ├── run_demo.py         # full demo with coloured terminal output
│   └── attacks.py          # all 4 attack classes
├── tests/
│   ├── __init__.py
│   ├── test_sss.py
│   ├── test_lagrange.py
│   ├── test_hkdf.py
│   ├── test_keyfile.py
│   ├── test_share_store.py
│   ├── test_ledger.py
│   ├── test_pbft.py
│   ├── test_registration.py
│   ├── test_authentication.py
│   ├── test_attacks.py
│   └── test_full_flow.py
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── requirements-docker.txt
├── Makefile
├── setup.sh
├── .github/
│   └── workflows/
│       └── ci.yml
└── README.md

════════════════════════════════════════════════════════════════
GLOBAL CONSTANTS — DEFINE IN crypto/__init__.py
════════════════════════════════════════════════════════════════

# SECP256K1 prime — all SSS arithmetic is mod this
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

# SSS parameters
N_NODES = 5       # total nodes
THRESHOLD = 3     # minimum shares to reconstruct (t)
F_NODES = 1       # Byzantine fault tolerance (f), where N = 3f+1

# Token TTL
IAT_TTL_SECONDS = 60

# Challenge expiry
CHALLENGE_TTL_SECONDS = 30

# PQC algorithm names — EXACT strings for liboqs
PQC_SIG_ALG   = "ML-DSA-65"
PQC_KEM_ALG   = "ML-KEM-768"

════════════════════════════════════════════════════════════════
MODULE 1: crypto/sss.py
════════════════════════════════════════════════════════════════

from crypto import P
import secrets

def generate_shares(secret: int, t: int, n: int, p: int = P) -> list[tuple[int, int]]:
    """
    Split secret S into n shares using a random degree-(t-1) polynomial
    over GF(p).

    Steps:
    1. Validate: 1 <= secret <= p-1
    2. Generate t-1 random coefficients a1..a(t-1) in [1, p-1]
       using secrets.randbelow(p-1) + 1  (never use random module)
    3. Build polynomial: f(x) = secret + a1*x + a2*x^2 + ... + a(t-1)*x^(t-1)
    4. Evaluate f(i) mod p for i in 1..n
    5. Return [(1, f(1)), (2, f(2)), ..., (n, f(n))]
    6. After returning, overwrite coefficients list with zeros:
       for i in range(len(coeffs)): coeffs[i] = 0
    """

def reconstruct_secret(shares: list[tuple[int, int]], p: int = P) -> int:
    """
    Reconstruct f(0) from exactly t (x, y) shares using Lagrange
    interpolation over GF(p). Calls lagrange_interpolate() from
    crypto/lagrange.py. Returns the integer secret.
    """

════════════════════════════════════════════════════════════════
MODULE 2: crypto/lagrange.py
════════════════════════════════════════════════════════════════

from crypto import P

def mod_inverse(a: int, p: int) -> int:
    """
    Modular multiplicative inverse using Fermat's little theorem.
    Returns a^(p-2) mod p.
    Raises ValueError if a == 0.
    """

def lagrange_interpolate(shares: list[tuple[int, int]], p: int = P) -> int:
    """
    Recover f(0) from t (x, y) points over GF(p).

    Formula (for each share i):
      basis_i = product over j≠i of: (-x_j) * mod_inverse(x_i - x_j, p)
      f(0) = sum over i of: y_i * basis_i   (all mod p)

    All arithmetic mod p throughout.
    Return the integer result in [0, p-1].
    """

════════════════════════════════════════════════════════════════
MODULE 3: crypto/feldman.py
════════════════════════════════════════════════════════════════

# We use SHA-3 hash commitments instead of g^x mod p
# because Feldman's discrete-log commitments are broken by Shor's algorithm.
# This is documented as a deliberate PQC design choice.

import hashlib, os
from crypto import P

def generate_commitments(
    coefficients: list[int],
    salt: bytes | None = None
) -> tuple[list[bytes], bytes]:
    """
    For each polynomial coefficient a_i, compute:
        C_i = SHA3-256(salt || i.to_bytes(4,'big') || a_i.to_bytes(32,'big'))

    Args:
        coefficients: list of polynomial coefficients [a0=S, a1, a2, ...]
        salt: 32 random bytes; generated fresh if None

    Returns:
        (commitments, salt)
        commitments: list of 32-byte digests, one per coefficient
        salt: the salt used (store this on the ledger alongside commitments)

    After computing commitments, do NOT zero coefficients here —
    the caller (register.py) is responsible for zeroing.
    """

def verify_share(
    share: tuple[int, int],
    commitments: list[bytes],
    salt: bytes,
    p: int = P
) -> bool:
    """
    Verify that share (x, y) is consistent with the published commitments.

    Method:
    1. Recompute expected_y = f(x) by evaluating the committed polynomial.
       But we only have commitments (hashes), not coefficients directly.
       So instead: each node verifies its own share at registration time
       by checking SHA3-256(salt || i.to_bytes(4,'big') || share_y.to_bytes(32,'big'))
       matches commitments[node_index].

    NOTE: This is simpler than full Feldman VSS cross-verification.
    Each node i verifies: SHA3-256(salt || (i-1).to_bytes(4,'big') || y.to_bytes(32,'big'))
    == commitments[i-1].
    Returns True if valid, False if tampered.

    This is explicitly documented in the README as a simplified PQC-safe
    commitment scheme. Full Feldman cross-verification is left as future work.
    """

════════════════════════════════════════════════════════════════
MODULE 4: crypto/hkdf.py
════════════════════════════════════════════════════════════════

import hashlib, hmac
from crypto import P

def derive_identity_secret(
    public_key_bytes: bytes,
    registration_nonce: bytes,
    password: str
) -> int:
    """
    Derive the identity secret S using HKDF-SHA3-256.

    Steps:
    1. IKM  = public_key_bytes + password.encode('utf-8')
    2. PRK  = hmac.new(key=registration_nonce, msg=IKM,
                       digestmod=hashlib.sha3_256).digest()
    3. OKM  = hmac.new(key=PRK,
                       msg=b'decidp-identity-secret-v1' + b'\x01',
                       digestmod=hashlib.sha3_256).digest()
    4. S    = int.from_bytes(OKM, 'big') % (P - 1) + 1
    5. Return S

    This is deterministic: same inputs → same S always.
    Different password → completely different S (no mathematical relationship).
    S is in range [1, P-1].
    """

def commitment_hash(S: int) -> str:
    """
    Return SHA3-256(S.to_bytes(32, 'big')).hexdigest()
    This is stored on the ledger during registration and
    compared during authentication.
    """

════════════════════════════════════════════════════════════════
MODULE 5: crypto/pqc.py
════════════════════════════════════════════════════════════════

"""
Post-quantum cryptography wrapper using liboqs.
ML-DSA-65 for signatures (replaces Ed25519).
ML-KEM-768 for key encapsulation (replaces ECDH).

IMPORTANT: This module requires the liboqs C library, which is only
available inside Docker (base image: openquantumsafe/liboqs-python:latest).

When running outside Docker (plain Python, for unit tests that don't
need PQC), this module falls back to Ed25519 via the cryptography
library and prints a warning. The fallback is clearly marked
PQC_AVAILABLE = False so callers can detect it.
"""

import os

try:
    import oqs
    PQC_AVAILABLE = True
except (ImportError, RuntimeError):
    PQC_AVAILABLE = False

# ── Signatures (ML-DSA-65) ─────────────────────────────────────

def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate a key pair.
    Returns (private_key_bytes, public_key_bytes).

    PQC mode:   ML-DSA-65 via liboqs.
    Fallback:   Ed25519 via cryptography library.
    Key sizes:
        ML-DSA-65:  private=4032 bytes, public=1952 bytes
        Ed25519:    private=32 bytes,   public=32 bytes
    """
    if PQC_AVAILABLE:
        with oqs.Signature("ML-DSA-65") as signer:
            public_key = signer.generate_keypair()
            private_key = signer.export_secret_key()
        return private_key, public_key
    else:
        import warnings
        warnings.warn("liboqs not available — using Ed25519 (NOT post-quantum secure)")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat, PrivateFormat, NoEncryption
        )
        priv = Ed25519PrivateKey.generate()
        priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pub_bytes  = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return priv_bytes, pub_bytes

def sign(private_key_bytes: bytes, message: bytes) -> bytes:
    """
    Sign message. Returns signature bytes.
    PQC mode:  ML-DSA-65.  Signature size: 3309 bytes.
    Fallback:  Ed25519.    Signature size: 64 bytes.
    """
    if PQC_AVAILABLE:
        with oqs.Signature("ML-DSA-65", private_key_bytes) as signer:
            return signer.sign(message)
    else:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        return Ed25519PrivateKey.from_private_bytes(private_key_bytes).sign(message)

def verify(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verify signature. Returns True if valid, False otherwise.
    MUST NOT raise exceptions under any input — catch all exceptions
    and return False.
    """
    try:
        if PQC_AVAILABLE:
            with oqs.Signature("ML-DSA-65") as verifier:
                return verifier.verify(message, signature, public_key_bytes)
        else:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            pub = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            pub.verify(signature, message)
            return True
    except Exception:
        return False

# ── Key Encapsulation (ML-KEM-768) ────────────────────────────

def kem_generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate a KEM key pair for a node.
    Returns (private_key_bytes, public_key_bytes).
    Used to encrypt shares for delivery to nodes.
    """
    if PQC_AVAILABLE:
        with oqs.KeyEncapsulation("ML-KEM-768") as kem:
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()
        return private_key, public_key
    else:
        # Fallback: generate a random 32-byte symmetric key pair
        # (simplified — real fallback would use X25519)
        import warnings, secrets
        warnings.warn("liboqs not available — KEM using random key (NOT secure)")
        key = secrets.token_bytes(32)
        return key, key  # same key for demo fallback only

def kem_encapsulate(recipient_public_key: bytes) -> tuple[bytes, bytes]:
    """
    Generate a shared secret for the recipient.
    Returns (ciphertext, shared_secret_32_bytes).
    Caller uses shared_secret as AES-256-GCM key to encrypt the share.
    """
    if PQC_AVAILABLE:
        with oqs.KeyEncapsulation("ML-KEM-768") as kem:
            ciphertext, shared_secret = kem.encap_secret(recipient_public_key)
        return ciphertext, shared_secret[:32]
    else:
        import secrets
        shared_secret = secrets.token_bytes(32)
        return shared_secret, shared_secret  # fallback: ciphertext == shared_secret

def kem_decapsulate(private_key_bytes: bytes, ciphertext: bytes) -> bytes:
    """
    Recover the shared secret from the ciphertext.
    Returns shared_secret_32_bytes.
    """
    if PQC_AVAILABLE:
        with oqs.KeyEncapsulation("ML-KEM-768", private_key_bytes) as kem:
            shared_secret = kem.decap_secret(ciphertext)
        return shared_secret[:32]
    else:
        return ciphertext  # fallback

════════════════════════════════════════════════════════════════
MODULE 6: crypto/keyfile.py
════════════════════════════════════════════════════════════════

"""
Password-protected keyfile for storing the user's private key locally.
The private key is encrypted with AES-256-GCM using a key derived
from the user's password via PBKDF2-SHA3.

File format (JSON):
{
  "version": 1,
  "alg": "ML-DSA-65" | "Ed25519",
  "salt": "<hex>",        # 32 bytes, random
  "nonce": "<hex>",       # 12 bytes, random
  "ciphertext": "<hex>",  # AES-256-GCM encrypted private key
  "public_key": "<hex>"   # plaintext public key for reference
}
"""

import hashlib, json, os, secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def _derive_aes_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from password using PBKDF2-HMAC-SHA3.
    Iterations: 600000 (NIST recommended minimum for PBKDF2).
    Returns 32 bytes.
    """
    return hashlib.pbkdf2_hmac(
        'sha3_256',
        password.encode('utf-8'),
        salt,
        iterations=600_000,
        dklen=32
    )

def save_keyfile(
    private_key_bytes: bytes,
    public_key_bytes: bytes,
    password: str,
    path: str,
    alg: str
) -> None:
    """
    Encrypt private_key_bytes with AES-256-GCM(PBKDF2(password))
    and write JSON keyfile to path.
    Creates parent directories if needed.
    """

def load_keyfile(path: str, password: str) -> tuple[bytes, bytes]:
    """
    Read keyfile, decrypt private key with password.
    Returns (private_key_bytes, public_key_bytes).
    Raises ValueError if password is wrong (AESGCM tag verification fails).
    Raises FileNotFoundError if path doesn't exist.
    """

════════════════════════════════════════════════════════════════
MODULE 7: node/share_store.py
════════════════════════════════════════════════════════════════

import sqlite3, os, hashlib, secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class ShareStore:
    """
    Encrypted per-node SQLite store mapping DID → SSS share.

    Schema:
    CREATE TABLE shares (
        did                TEXT PRIMARY KEY,
        x_coord            INTEGER NOT NULL,
        y_coord_encrypted  BLOB NOT NULL,   -- AES-256-GCM(y.to_bytes(32,'big'))
        aes_nonce          BLOB NOT NULL,   -- 12-byte random nonce
        share_hash         TEXT NOT NULL,   -- SHA3-256(x||y) for integrity check
        feldman_commitment BLOB,            -- SHA3-256 commitment for this share
        registered_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """

    def __init__(self, node_id: int, data_dir: str = "data"):
        """
        Create data/{data_dir}/node_{node_id}/ directory.
        Generate a fresh AES-256 encryption key if no keyfile exists,
        otherwise load it.
        Key stored at data/node_{node_id}/store.key (binary, 32 bytes).
        Open (or create) SQLite DB at data/node_{node_id}/shares.db.
        """

    def store_share(
        self,
        did: str,
        x: int,
        y: int,
        feldman_commitment: bytes | None = None
    ) -> None:
        """
        Encrypt y with AES-256-GCM using stored node key.
        AAD (additional authenticated data) = did.encode() — binds
        ciphertext to this specific DID, preventing ciphertext swapping.
        Store x_coord, y_encrypted, nonce, sha3_256(str(x)+str(y)), commitment.
        Use INSERT OR REPLACE.
        """

    def get_share(self, did: str) -> tuple[int, int] | None:
        """
        Decrypt and return (x, y) for given DID.
        Verify sha3_256(str(x)+str(y)) matches stored share_hash.
        Returns None if DID not found.
        Raises ValueError if integrity check fails (tampered share).
        """

    def delete_share(self, did: str) -> None:
        """Delete share row for DID. No-op if not found."""

    def has_share(self, did: str) -> bool:
        """Return True if share exists for DID."""

════════════════════════════════════════════════════════════════
MODULE 8: node/partial_proof.py
════════════════════════════════════════════════════════════════

import hashlib
from crypto import P

def compute_partial_proof(
    share: tuple[int, int],
    challenge_nonce: bytes,
    node_id: int,
    p: int = P
) -> dict:
    """
    Compute this node's contribution to the authentication proof.

    Steps:
    1. H = int(hashlib.sha3_256(challenge_nonce).hexdigest(), 16) % p
    2. partial_value = (share[1] * H) % p
       where share[1] is y = f(node_id) = the SSS share value
    3. Return:
       {
         "node_id":       node_id,
         "x":             share[0],       # x-coordinate of share
         "partial_value": partial_value,  # y * H mod p
         "H":             H,              # challenge hash (same for all honest nodes)
         "challenge_hash": hashlib.sha3_256(challenge_nonce).hexdigest()
       }

    Security note:
    partial_value alone reveals nothing about y because H is a random
    oracle output — this is a blinded share contribution.
    """

def recover_secret_from_partial_proofs(
    proofs: list[dict],
    p: int = P
) -> int:
    """
    Recover S from t honest partial proofs.

    Steps:
    1. Extract H from proofs[0]['H']  (all honest proofs have same H)
    2. H_inv = pow(H, p-2, p)  (Fermat's little theorem)
    3. Reconstruct original shares: (x_i, partial_value_i * H_inv % p)
    4. Run Lagrange interpolation on these recovered shares
    5. Return S_reconstructed

    Raises ValueError if fewer than THRESHOLD proofs provided.
    """

════════════════════════════════════════════════════════════════
MODULE 9: node/pbft.py
════════════════════════════════════════════════════════════════

"""
Simplified 3-phase PBFT for 5 nodes (f=1).

This is a simplified implementation without view changes or
checkpointing. It is sufficient to demonstrate Byzantine fault
tolerance for a prototype. Full PBFT (Castro-Liskov 1999) with
view changes is documented as future work.

Nodes communicate via the transport layer (LocalTransport or
HTTPTransport) — this module contains only the consensus logic.
"""

from crypto import N_NODES, THRESHOLD, F_NODES

class PBFTRound:
    """
    Represents one authentication consensus round.
    """

    def __init__(self, round_id: str, n: int = N_NODES, f: int = F_NODES):
        self.round_id   = round_id
        self.n          = n
        self.f          = f
        self.quorum     = 2 * f + 1   # = 3
        self.prepare_messages: list[dict]  = []
        self.committed  = False
        self.result: list[dict] | None = None

    def add_prepare_message(self, proof: dict) -> None:
        """
        Add a prepare message (partial proof) from a node.
        A prepare message is:
        {
          "node_id": int,
          "x": int,
          "partial_value": int,
          "H": int,
          "challenge_hash": str
        }
        Ignore duplicates from same node_id.
        """

    def try_commit(self) -> list[dict] | None:
        """
        Attempt to reach quorum and commit.

        Byzantine detection algorithm:
        1. Group proofs by challenge_hash.
           Any proof with a different challenge_hash than the majority
           is immediately discarded (wrong H means wrong challenge).
        2. Among proofs with matching challenge_hash, we cannot directly
           compare partial_values (each node has a different x, so
           different partial_value is expected and correct).
           Instead: verify that all proofs have consistent H values.
           A Byzantine node might submit H != SHA3-256(challenge_nonce),
           but since H is derived deterministically from the challenge,
           all honest nodes produce the same H.
        3. Accept all proofs with matching challenge_hash as honest.
           Discard any with mismatched challenge_hash or H.
        4. If len(accepted) >= quorum (3):
           - self.committed = True
           - self.result = accepted proofs
           - Return accepted[:THRESHOLD]  (exactly t=3 proofs for reconstruction)
        5. If len(accepted) < quorum: return None.

        Log each discarded proof:
        print(f"[PBFT] Node {node_id} proof DISCARDED: challenge_hash mismatch")
        """

    @property
    def is_committed(self) -> bool:
        return self.committed

def run_pbft_round(
    round_id: str,
    partial_proofs: list[dict]
) -> list[dict] | None:
    """
    Run a complete PBFT round given all collected partial proofs.
    Returns list of THRESHOLD honest proofs on success, None on failure.
    This is the main entry point called by authenticate.py.
    """
    pbft = PBFTRound(round_id)
    for proof in partial_proofs:
        pbft.add_prepare_message(proof)
    return pbft.try_commit()

════════════════════════════════════════════════════════════════
MODULE 10: node/transport.py
════════════════════════════════════════════════════════════════

"""
Transport abstraction — swap between local (in-process) and HTTP
without changing any other code.

Usage:
    NODE_TRANSPORT=local  → LocalTransport (default, no network needed)
    NODE_TRANSPORT=http   → HTTPTransport  (real network, Docker/5 machines)

All other modules import get_transport() and call:
    transport.send_partial_proof(node_id, proof)
    transport.get_partial_proof(node_id, did, challenge_nonce)
"""

import os
from abc import ABC, abstractmethod

class NodeTransport(ABC):

    @abstractmethod
    def request_partial_proof(
        self,
        target_node_id: int,
        did: str,
        challenge_nonce_hex: str
    ) -> dict | None:
        """
        Ask target node to compute and return its partial proof.
        Returns proof dict on success, None if node is offline/failed.
        """

class LocalTransport(NodeTransport):
    """
    In-process transport — nodes are Python objects in the same process.
    Used for: unit tests, single-machine demo (localhost).
    In real deployment this would be replaced by gRPC + mTLS.
    """

    def __init__(self):
        self._nodes: dict[int, object] = {}  # node_id → Node instance

    def register_node(self, node_id: int, node: object) -> None:
        self._nodes[node_id] = node

    def request_partial_proof(
        self,
        target_node_id: int,
        did: str,
        challenge_nonce_hex: str
    ) -> dict | None:
        node = self._nodes.get(target_node_id)
        if node is None or not node.online:
            return None
        try:
            return node.compute_partial_proof(did, bytes.fromhex(challenge_nonce_hex))
        except Exception as e:
            print(f"[Transport] Node {target_node_id} error: {e}")
            return None

class HTTPTransport(NodeTransport):
    """
    Real HTTP transport — each node is a separate process/container.
    Reads peer addresses from environment:
        NODE_PEERS=192.168.1.101:8001,192.168.1.102:8002,...
    or from docker-compose service names:
        NODE_PEERS=node1:8001,node2:8002,...
    """

    def __init__(self):
        import httpx
        peers_env = os.environ.get("NODE_PEERS", "")
        self._peers: dict[int, str] = {}
        if peers_env:
            for i, addr in enumerate(peers_env.split(","), start=1):
                self._peers[i] = addr.strip()
        self._client = httpx.Client(timeout=5.0)

    def request_partial_proof(
        self,
        target_node_id: int,
        did: str,
        challenge_nonce_hex: str
    ) -> dict | None:
        addr = self._peers.get(target_node_id)
        if not addr:
            return None
        try:
            url = f"http://{addr}/internal/partial_proof"
            resp = self._client.post(url, json={
                "did": did,
                "challenge_nonce": challenge_nonce_hex
            })
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as e:
            print(f"[Transport] HTTP error node {target_node_id}: {e}")
            return None

def get_transport() -> NodeTransport:
    """
    Factory. Returns LocalTransport or HTTPTransport based on
    NODE_TRANSPORT environment variable (default: 'local').
    """
    mode = os.environ.get("NODE_TRANSPORT", "local").lower()
    if mode == "http":
        return HTTPTransport()
    return LocalTransport()

════════════════════════════════════════════════════════════════
MODULE 11: node/node.py
════════════════════════════════════════════════════════════════

from node.share_store import ShareStore
from node.partial_proof import compute_partial_proof

class Node:
    """
    A single BFT identity node. Holds one SSS share per registered DID.
    Exposes one public method: compute_partial_proof().
    """

    def __init__(self, node_id: int, data_dir: str = "data"):
        self.node_id    = node_id
        self.online     = True          # set False to simulate crash
        self.byzantine  = False         # set True to simulate Byzantine
        self.share_store = ShareStore(node_id, data_dir)

    def compute_partial_proof(
        self,
        did: str,
        challenge_nonce: bytes
    ) -> dict:
        """
        1. If not self.online: raise NodeOfflineError
        2. Retrieve share (x, y) from share_store for this DID
        3. If share not found: raise ShareNotFoundError
        4. If self.byzantine:
               import secrets, crypto
               fake_value = secrets.randbelow(P - 1) + 1
               return a proof dict with partial_value=fake_value
               and the correct x and H values
               (honest-looking structure, wrong math — this is what
                a real compromised node would do)
        5. Compute and return real partial proof via
           compute_partial_proof(share, challenge_nonce, self.node_id)
        """

class NodeOfflineError(Exception):
    pass

class ShareNotFoundError(Exception):
    pass

════════════════════════════════════════════════════════════════
MODULE 12: ledger/ledger.py
════════════════════════════════════════════════════════════════

"""
Append-only audit ledger with SHA-3 hash chain.
Simulates a distributed ledger using SQLite.
Every entry is cryptographically linked to the previous one.
Tampering with any entry invalidates all subsequent hashes.
"""

import sqlite3, hashlib, json, time, os
from typing import Any

ENTRY_TYPES = {
    'DID_REGISTER',   # new user registered
    'AUTH_SUCCESS',   # authentication succeeded
    'AUTH_FAIL',      # authentication failed
    'SHARE_REVOKE',   # share deleted (offboarding)
}

class Ledger:

    def __init__(self, db_path: str = "data/ledger.db"):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS entries (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_type     TEXT    NOT NULL,
                did            TEXT    NOT NULL,
                data_json      TEXT    NOT NULL,
                timestamp      REAL    NOT NULL,
                entry_hash     TEXT    NOT NULL,
                previous_hash  TEXT    NOT NULL
            )
        ''')
        self.conn.commit()

    def _last_hash(self) -> str:
        row = self.conn.execute(
            'SELECT entry_hash FROM entries ORDER BY id DESC LIMIT 1'
        ).fetchone()
        return row[0] if row else '0' * 64

    def append(self, entry_type: str, did: str, data: dict[str, Any]) -> str:
        """
        Append entry and return its entry_hash.
        entry_hash = SHA3-256(previous_hash || entry_type || did || data_json || timestamp)
        data_json is json.dumps(data, sort_keys=True).
        """

    def verify_chain(self) -> bool:
        """
        Walk all entries in order, recompute each hash from scratch,
        verify it matches stored entry_hash and stored previous_hash
        matches the previous entry's entry_hash.
        Return True if chain is intact, False if any entry is tampered.
        """

    def get_did_document(self, did: str) -> dict | None:
        """
        Return data_json parsed as dict from the most recent
        DID_REGISTER entry for this did. None if not found.
        """

    def get_commitment_hash(self, did: str) -> str | None:
        """Return data['commitment_hash'] from DID_REGISTER entry."""

    def get_registration_nonce(self, did: str) -> bytes | None:
        """
        Return bytes.fromhex(data['nonce']) from DID_REGISTER entry.
        """

    def get_feldman_commitments(self, did: str) -> list[bytes] | None:
        """
        Return list of bytes.fromhex(c) for each commitment hex string
        in data['feldman_commitments'] from DID_REGISTER entry.
        """

    def get_public_key(self, did: str) -> bytes | None:
        """Return bytes.fromhex(data['public_key']) from DID_REGISTER."""

    def get_all_entries(self) -> list[dict]:
        """
        Return all entries as list of dicts for display in demo.
        Each dict: {id, entry_type, did, data, timestamp, entry_hash}
        """

════════════════════════════════════════════════════════════════
MODULE 13: authentication/challenge.py
════════════════════════════════════════════════════════════════

import secrets, time, uuid
from crypto import CHALLENGE_TTL_SECONDS

class ChallengeManager:
    """
    Issues and tracks single-use challenge nonces.
    Challenges expire after CHALLENGE_TTL_SECONDS (30s).
    A challenge can only be used ONCE — it is deleted on first use.
    This prevents replay attacks.
    """

    def __init__(self):
        # challenge_id (str) → {'nonce': bytes, 'did': str, 'expires_at': float}
        self._pending: dict[str, dict] = {}

    def issue(self, did: str) -> dict:
        """
        Generate a fresh 32-byte random nonce.
        Store under a fresh UUID challenge_id with expiry.
        Return:
        {
          "challenge_id": str (UUID),
          "nonce":        str (hex, 32 bytes),
          "expires_in":   int (seconds)
        }
        """

    def consume(self, challenge_id: str) -> bytes | None:
        """
        Validate and consume a challenge.
        1. Look up challenge_id in _pending
        2. If not found: return None
        3. If expired (time.time() > expires_at): delete it, return None
        4. Delete from _pending (SINGLE USE)
        5. Return nonce bytes
        """

    def _cleanup_expired(self) -> None:
        """Remove all expired challenges. Call this periodically."""
        now = time.time()
        expired = [cid for cid, v in self._pending.items()
                   if v['expires_at'] < now]
        for cid in expired:
            del self._pending[cid]

════════════════════════════════════════════════════════════════
MODULE 14: authentication/iat.py
════════════════════════════════════════════════════════════════

"""
Identity Assertion Token (IAT).
Structured like a JWT but issued by the decentralised system.
Signed with the SYSTEM private key (ML-DSA-65 or Ed25519 fallback).
TTL: 60 seconds.
"""

import json, time, uuid, hashlib, base64
from crypto import IAT_TTL_SECONDS
from crypto.pqc import sign as pqc_sign, verify as pqc_verify

# System key pair — in production, loaded from a Hardware Security Module.
# For prototype: generated fresh at startup, stored in data/system.key
_system_private_key: bytes | None = None
_system_public_key:  bytes | None = None

def init_system_keys(data_dir: str = "data") -> None:
    """
    Load system keys from data/system.key if it exists,
    otherwise generate a new key pair, save private key to
    data/system.key (binary) and public key to data/system.pub.
    Sets module-level _system_private_key and _system_public_key.
    """

def issue(did: str, quorum_nodes: list[int]) -> str:
    """
    Issue a signed IAT.

    Payload (JSON, sorted keys):
    {
      "sub":    did,
      "iat":    current unix timestamp (int),
      "exp":    iat + IAT_TTL_SECONDS,
      "jti":    str(uuid.uuid4()),
      "quorum": sorted list of node_ids that formed quorum,
      "iss":    "did:decidp:system"
    }

    Token format (3 base64url parts joined by '.'):
      header.payload.signature
    header = base64url({"alg": "ML-DSA-65", "typ": "DECIDP-IAT"})
    payload = base64url(json.dumps(payload_dict, sort_keys=True))
    signature = base64url(pqc_sign(private_key, header + '.' + payload))

    Return the full token string.
    """

def verify_iat(token: str) -> dict | None:
    """
    Verify token signature and expiry.
    Returns payload dict if valid and not expired.
    Returns None if signature invalid, expired, or malformed.
    Never raises exceptions.
    """

════════════════════════════════════════════════════════════════
MODULE 15: registration/register.py
════════════════════════════════════════════════════════════════

"""
Full registration flow orchestrator.

COMPLETE FLOW:
1.  Generate ML-DSA-65 key pair (PQC) via crypto/pqc.py
2.  Generate DID = "did:decidp:" + sha3_256(public_key_bytes).hexdigest()[:16]
3.  Generate registration_nonce = secrets.token_bytes(32)
4.  Derive S = HKDF-SHA3(public_key_bytes, registration_nonce, password)
5.  Validate S in [1, P-1]
6.  Generate SSS shares: generate_shares(S, t=THRESHOLD, n=N_NODES)
7.  Generate Feldman commitments for shares
8.  For each node i=1..N_NODES:
        a. share = shares[i-1]  →  (i, f(i))
        b. Get node's KEM public key (generated at node startup,
           stored at data/node_{i}/kem.pub)
        c. kem_ciphertext, shared_secret = kem_encapsulate(node_kem_pub)
        d. Encrypt share[1] (y value) with AES-256-GCM(shared_secret):
               aes = AESGCM(shared_secret)
               nonce = secrets.token_bytes(12)
               encrypted_y = aes.encrypt(nonce, share[1].to_bytes(32,'big'), did.encode())
           NOTE: In LocalTransport mode the share is passed directly to
           the node object. In HTTPTransport mode the encrypted share and
           kem_ciphertext are sent via HTTP POST to node's /internal/store_share.
        e. node.share_store.store_share(did, share[0], share[1],
                                        feldman_commitment=commitments[i-1])
9.  Publish to ledger (DID_REGISTER entry):
        {
          "public_key":           public_key_bytes.hex(),
          "commitment_hash":      sha3_256(S.to_bytes(32,'big')).hexdigest(),
          "nonce":                registration_nonce.hex(),
          "feldman_commitments":  [c.hex() for c in commitments],
          "feldman_salt":         salt.hex(),
          "registered_at":        current unix timestamp
        }
10. ZERO S AND COEFFICIENTS FROM MEMORY:
        S = 0
        for i in range(len(shares)): shares[i] = (0, 0)
        del S, shares
        import ctypes
        # Best-effort zeroing — Python GC is not guaranteed to release
        # immediately; this is documented as a known limitation.
11. Encrypt private key into keyfile using crypto/keyfile.py:
        save_keyfile(private_key, public_key, password,
                     path=f"~/.decidp/{did}.key", alg="ML-DSA-65")
12. Return:
        {
          "status":     "success",
          "did":        did,
          "public_key": public_key_bytes.hex(),
          "keyfile_path": "~/.decidp/{did}.key",
          "message":    "Private key saved to keyfile. Keep your password safe."
        }
        DO NOT include private_key in response.
"""

class RegistrationService:

    def __init__(self, nodes: list, ledger, data_dir: str = "data"):
        self.nodes    = nodes    # list of Node objects (index 0 = node_id 1)
        self.ledger   = ledger
        self.data_dir = data_dir

    def register(self, password: str) -> dict:
        """Implements the complete 12-step flow above."""

════════════════════════════════════════════════════════════════
MODULE 16: authentication/authenticate.py
════════════════════════════════════════════════════════════════

"""
Full authentication flow orchestrator.

COMPLETE FLOW:
1.  Validate challenge_id is still pending (not expired/consumed):
        nonce = challenge_manager.consume(challenge_id)
        if nonce is None:
            return fail("challenge_expired_or_invalid")

2.  Look up DID Document from ledger:
        public_key_bytes = ledger.get_public_key(did)
        if public_key_bytes is None:
            return fail("did_not_found")

3.  Verify Ed25519/ML-DSA-65 signature:
        signed_message = nonce + did.encode('utf-8')
        if not pqc_verify(public_key_bytes, signed_message, signature_bytes):
            ledger.append('AUTH_FAIL', did, {"reason": "invalid_signature"})
            return fail("invalid_signature")

4.  Collect partial proofs from all N_NODES nodes:
        proofs = []
        for node in nodes:
            proof = transport.request_partial_proof(
                node.node_id, did, nonce.hex()
            )
            if proof is not None:
                proofs.append(proof)
        print status for each node (online/offline/responded)

5.  Run PBFT consensus:
        round_id = sha3_256(nonce + did.encode()).hexdigest()[:16]
        honest_proofs = run_pbft_round(round_id, proofs)
        if honest_proofs is None:
            ledger.append('AUTH_FAIL', did, {"reason": "quorum_not_reached"})
            return fail("quorum_not_reached")

6.  Reconstruct S from honest partial proofs:
        S_reconstructed = recover_secret_from_partial_proofs(honest_proofs)

7.  Verify commitment hash:
        computed   = sha3_256(S_reconstructed.to_bytes(32,'big')).hexdigest()
        stored     = ledger.get_commitment_hash(did)
        if computed != stored:
            S_reconstructed = 0
            del S_reconstructed
            ledger.append('AUTH_FAIL', did, {"reason": "commitment_mismatch"})
            return fail("commitment_mismatch")

8.  ZERO S_reconstructed:
        S_reconstructed = 0
        del S_reconstructed

9.  Issue IAT:
        quorum_nodes = [p['node_id'] for p in honest_proofs]
        token = iat.issue(did, quorum_nodes)
        ledger.append('AUTH_SUCCESS', did, {
            "quorum_nodes": quorum_nodes,
            "token_jti": <extract jti from token>
        })
        return {
            "status":     "success",
            "iat":        token,
            "expires_in": IAT_TTL_SECONDS
        }

Helper:
def fail(reason: str) -> dict:
    return {"status": "failed", "reason": reason, "iat": None, "expires_in": None}
"""

class AuthenticationService:

    def __init__(self, nodes: list, ledger, challenge_manager,
                 transport, data_dir: str = "data"):
        self.nodes             = nodes
        self.ledger            = ledger
        self.challenge_manager = challenge_manager
        self.transport         = transport
        self.data_dir          = data_dir

    def authenticate(
        self,
        did: str,
        challenge_id: str,
        signature_hex: str
    ) -> dict:
        """Implements the complete 9-step flow above."""

════════════════════════════════════════════════════════════════
MODULE 17: api/main.py
════════════════════════════════════════════════════════════════

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from contextlib import asynccontextmanager
import os

# ── Startup ───────────────────────────────────────────────────
# Initialise all components at startup:
#   - 5 Node instances
#   - LocalTransport or HTTPTransport (from NODE_TRANSPORT env)
#   - Ledger instance
#   - ChallengeManager instance
#   - RegistrationService instance
#   - AuthenticationService instance
#   - init_system_keys()
# All stored as module-level singletons.

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise all singletons on startup."""
    # ... init code here ...
    yield
    # cleanup if needed

app = FastAPI(
    title="Decentralised IDP",
    version="1.0.0",
    description="Post-quantum decentralised identity provider using SSS + BFT",
    lifespan=lifespan
)

# ── Models ────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    password: str

class RegisterResponse(BaseModel):
    status: str
    did: str | None = None
    public_key: str | None = None
    keyfile_path: str | None = None
    message: str | None = None
    error: str | None = None

class ChallengeRequest(BaseModel):
    did: str

class ChallengeResponse(BaseModel):
    challenge_id: str
    nonce: str
    expires_in: int

class AuthRequest(BaseModel):
    did: str
    challenge_id: str
    signature: str   # hex-encoded ML-DSA-65 or Ed25519 signature

class AuthResponse(BaseModel):
    status: str
    iat: str | None = None
    expires_in: int | None = None
    reason: str | None = None

# ── Endpoints ─────────────────────────────────────────────────

@app.post("/register", response_model=RegisterResponse)
async def register(req: RegisterRequest):
    """Register a new user. Returns DID and keyfile path."""

@app.post("/challenge", response_model=ChallengeResponse)
async def get_challenge(req: ChallengeRequest):
    """Issue a fresh challenge nonce for a DID."""

@app.post("/authenticate", response_model=AuthResponse)
async def authenticate(req: AuthRequest):
    """Authenticate using a signed challenge. Returns IAT on success."""

@app.get("/verify")
async def verify_token(token: str):
    """
    Verify an IAT token.
    Returns {"valid": bool, "did": str|None, "expires_at": int|None}
    """

@app.get("/health")
async def health():
    """
    Returns system health:
    {"status": "ok", "nodes": [{"id":1,"online":True}, ...],
     "pqc_available": bool, "ledger_chain_valid": bool}
    """

# ── Internal endpoint (node-to-node, HTTP transport only) ─────

@app.post("/internal/partial_proof")
async def internal_partial_proof(body: dict):
    """
    Called by HTTPTransport.request_partial_proof().
    Body: {"did": str, "challenge_nonce": str (hex)}
    Returns partial proof dict.
    Only active when NODE_TRANSPORT=http.
    Returns 403 if NODE_TRANSPORT=local.
    """

════════════════════════════════════════════════════════════════
MODULE 18: simulate/attacks.py
════════════════════════════════════════════════════════════════

"""
Four attack classes for the live demonstration.
Each has trigger() to activate and reset() to restore normal state.
"""

from crypto import P, THRESHOLD

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
        print(f"\n💀 [ATTACK 1] Node {self.target_id} is now OFFLINE\n")

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
        print(f"\n🔴 [ATTACK 2] Node {self.target_id} is now BYZANTINE")
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
        ledger
    ):
        assert len(attacker_node_ids) == 2
        self.attacker_ids = attacker_node_ids
        self.nodes        = {n.node_id: n for n in nodes}
        self.ledger       = ledger

    def trigger(self, target_did: str) -> bool:
        """
        1. Print: "Compromised nodes X and Y pooling shares..."
        2. Steal shares from both compromised nodes' ShareStores
        3. Print each stolen share (x, hex(y)[:16]...)
        4. Print: "Attempting Lagrange interpolation with 2 shares (need 3)..."
        5. Call lagrange_interpolate on 2 shares → fake_S
        6. Compute sha3_256(fake_S) and compare to ledger commitment
        7. Print result:
           - If no match (expected):
             "✅ ATTACK FAILED — 2 shares reveal ZERO information about S"
             "   Reconstructed hash: <computed>..."
             "   Real commitment:    <stored>..."
             "   These will NEVER match with fewer than t=3 shares."
           - If match (should never happen):
             "❌ CRITICAL: attack succeeded — this is a bug"
        8. Return True if attack succeeded (should always be False)
        """

class ReplayAttack:
    """
    Attack 4: Intercepts a valid auth message and tries to reuse it.
    Demonstrates single-use challenge nonces.
    """
    def __init__(self, auth_service):
        self.auth_service  = auth_service
        self._intercepted  = None

    def intercept(self, did: str, challenge_id: str, signature_hex: str):
        self._intercepted = {
            "did": did,
            "challenge_id": challenge_id,
            "signature": signature_hex
        }
        print(f"\n🔴 [ATTACK 4] Intercepted auth message")
        print(f"   challenge_id: {challenge_id[:12]}...\n")

    def replay(self) -> dict:
        """
        Call auth_service.authenticate() with the intercepted message.
        Print result:
          "✅ REPLAY ATTACK FAILED — challenge nonce already consumed"
            or
          "❌ REPLAY ATTACK SUCCEEDED — this is a bug"
        Return the auth result dict.
        """

════════════════════════════════════════════════════════════════
MODULE 19: simulate/run_demo.py
════════════════════════════════════════════════════════════════

"""
Full coloured terminal demonstration.
Uses ANSI colour codes — works in WSL2 terminal.

Run with: python simulate/run_demo.py
Or:       make demo
"""

Colour codes to use:
    RESET  = "\033[0m"
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"

def separator(title: str):
    print(f"\n{BOLD}{BLUE}{'═'*60}{RESET}")
    print(f"{BOLD}{BLUE}  {title}{RESET}")
    print(f"{BOLD}{BLUE}{'═'*60}{RESET}\n")

Demo sequence (implement exactly this order,
with input("  ↵ Press Enter to continue...") between each phase):

    separator("SETUP — Initialising 5-Node BFT Network")
    - Create 5 Node instances
    - Create LocalTransport, register all nodes
    - Create Ledger, ChallengeManager
    - Create RegistrationService, AuthenticationService
    - init_system_keys()
    - Print each node: "[Node 1] Online ✓  Share store ready ✓"
    - Print PQC status: "[PQC] ML-DSA-65 available ✓" or "[PQC] ⚠ Fallback to Ed25519"

    separator("PHASE 1 — User Registration")
    - Register user "alice" with password "AliceSecure@2026"
    - Print each step as it happens
    - Print: "DID issued: did:decidp:..."
    - Print: "S split into 5 shares (3-of-5 threshold)"
    - Print each "Share i → Node i ✓"
    - Print: "S zeroed from memory ✓"
    - Print: "Commitment hash on ledger ✓"

    separator("PHASE 2 — Normal Authentication")
    - Issue challenge, sign with alice's key (loaded from keyfile)
    - Print each PBFT step
    - Print: "IAT issued ✓ (expires in 60s)"
    - Print first 40 chars of token

    separator("ATTACK 1 — Node Crash")
    - Crash Node 3
    - Attempt authentication
    - Print result: "System authenticated with 4 nodes ✓ (Node 3 offline)"
    - Reset Node 3

    separator("ATTACK 2 — Byzantine Wrong Proof")
    - Set Node 3 byzantine
    - Attempt authentication
    - Print: "Node 3 sent WRONG partial proof"
    - Print: "BFT detected and discarded Node 3 ✗"
    - Print: "Authentication succeeded with 4 honest nodes ✓"
    - Reset Node 3

    separator("ATTACK 3 — Share Theft (2 Compromised Nodes)")
    - Run ShareTheftAttack on nodes 2 and 3
    - Print full output from attack.trigger()

    separator("ATTACK 4 — Replay Attack")
    - Perform one legitimate auth, intercept the message
    - Try to replay it
    - Print result

    separator("WRONG PASSWORD")
    - Try to load keyfile with wrong password
    - Print: "❌ Wrong password — keyfile decryption failed ✓"

    separator("AUDIT LOG")
    - Print all ledger entries in a table
    - Print chain integrity result

    separator("SUMMARY")
    - Print the attack summary table:

    ╔══════════════════════════╦════════════════════════╦══════════╗
    ║ Attack                   ║ Defence                ║ Result   ║
    ╠══════════════════════════╬════════════════════════╬══════════╣
    ║ Node crash               ║ BFT fault tolerance    ║ BLOCKED  ║
    ║ Byzantine wrong proof    ║ PBFT outlier detection ║ BLOCKED  ║
    ║ 2-node share theft       ║ SSS threshold (t=3)    ║ BLOCKED  ║
    ║ Replay intercepted auth  ║ Single-use nonces      ║ BLOCKED  ║
    ║ Wrong password           ║ AES-GCM keyfile        ║ BLOCKED  ║
    ╚══════════════════════════╩════════════════════════╩══════════╝

════════════════════════════════════════════════════════════════
TESTS — tests/ DIRECTORY
════════════════════════════════════════════════════════════════

Write pytest tests for every module. Minimum requirements:

test_sss.py:
  - test_reconstruct_all_combinations: test all C(5,3)=10 subsets,
    each must reconstruct correct S
  - test_two_shares_fail: all C(5,2)=10 pairs, none must equal S
  - test_different_configs: t=2,n=3 and t=4,n=7
  - test_secret_range: S=1, S=P-1, S=random

test_lagrange.py:
  - test_interpolate_known: f(x)=7+3x+2x², shares at x=1,2,3,
    f(0) must equal 7
  - test_mod_inverse: a*mod_inverse(a,P) % P == 1

test_hkdf.py:
  - test_deterministic: same inputs → same S always
  - test_different_password: different password → different S
  - test_commitment_hash: sha3_256(S) matches commitment_hash(S)

test_keyfile.py:
  - test_roundtrip: save then load with correct password succeeds
  - test_wrong_password: load with wrong password raises ValueError
  - test_file_not_found: raises FileNotFoundError

test_share_store.py:
  - test_store_and_retrieve: store (x,y), retrieve, must match
  - test_missing_did: get_share for unknown DID returns None
  - test_delete: store then delete, then get returns None

test_ledger.py:
  - test_chain_valid: append 5 entries, verify_chain() True
  - test_chain_tampered: modify entry 2, verify_chain() False
  - test_get_commitment_hash: retrieve what was stored
  - test_get_public_key: retrieve what was stored

test_pbft.py:
  - test_quorum_reached_4_honest: 4 honest + 1 byzantine → success
  - test_quorum_reached_3_honest: 3 honest + 2 byzantine → success
  - test_quorum_failed_2_honest: 2 honest + 3 byzantine → None
  - test_byzantine_detection: byzantine proof has wrong challenge_hash,
    verify it is discarded

test_registration.py:
  - test_register_success: registers without error, returns DID
  - test_shares_distributed: after registration, all 5 nodes
    have a share for the DID
  - test_commitment_on_ledger: commitment_hash on ledger matches
    sha3_256(S) — but we cannot verify S directly (it was zeroed).
    Instead: re-derive S from stored nonce + public_key + password
    and check hash matches.

test_authentication.py:
  - test_auth_success: correct password → IAT issued
  - test_auth_wrong_signature: tampered signature → invalid_signature
  - test_auth_expired_challenge: wait 31s → challenge_expired
  - test_auth_wrong_did: unknown DID → did_not_found
  - test_iat_verify: issued token verifies correctly
  - test_iat_expired: token with past exp → verify returns None

test_attacks.py:
  - test_crash_attack: crash node 3, auth still succeeds
  - test_byzantine_attack: byzantine node 3, auth still succeeds
  - test_share_theft: 2 stolen shares → reconstruction fails
  - test_replay_attack: replay used challenge → fails

test_full_flow.py:
  - test_end_to_end: register → challenge → sign → authenticate
    → verify IAT → all pass in sequence

Use pytest fixtures in conftest.py to create shared:
  - nodes (5 Node instances)
  - transport (LocalTransport with all nodes registered)
  - ledger (fresh temp SQLite path per test)
  - challenge_manager
  - registration_service
  - authentication_service

Use tmp_path pytest fixture for all file paths to avoid
test pollution.

════════════════════════════════════════════════════════════════
DOCKERFILE
════════════════════════════════════════════════════════════════

FROM openquantumsafe/liboqs-python:latest

WORKDIR /app

# Install Python dependencies
COPY requirements-docker.txt .
RUN pip install --no-cache-dir -r requirements-docker.txt

# Copy source
COPY . .

# Create data directory
RUN mkdir -p data

# Default: run the API on port 8000
# Override CMD for node-specific startup
ENV NODE_TRANSPORT=http
ENV NODE_ID=1
ENV NODE_PORT=8000

CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port ${NODE_PORT}"]

════════════════════════════════════════════════════════════════
DOCKER-COMPOSE.YML
════════════════════════════════════════════════════════════════

version: "3.9"

services:
  node1:
    build: .
    environment:
      NODE_ID: "1"
      NODE_PORT: "8001"
      NODE_TRANSPORT: "http"
      NODE_PEERS: "node1:8001,node2:8002,node3:8003,node4:8004,node5:8005"
    ports: ["8001:8001"]
    volumes: ["./data/node1:/app/data"]
    networks: [decidp]
    command: uvicorn api.main:app --host 0.0.0.0 --port 8001

  node2:
    build: .
    environment:
      NODE_ID: "2"
      NODE_PORT: "8002"
      NODE_TRANSPORT: "http"
      NODE_PEERS: "node1:8001,node2:8002,node3:8003,node4:8004,node5:8005"
    ports: ["8002:8002"]
    volumes: ["./data/node2:/app/data"]
    networks: [decidp]
    command: uvicorn api.main:app --host 0.0.0.0 --port 8002

  # node3, node4, node5: same pattern with NODE_ID and port incremented

  # Client service for running the demo
  demo:
    build: .
    environment:
      NODE_TRANSPORT: "http"
      NODE_PEERS: "node1:8001,node2:8002,node3:8003,node4:8004,node5:8005"
    depends_on: [node1, node2, node3, node4, node5]
    networks: [decidp]
    command: python simulate/run_demo.py

networks:
  decidp:
    driver: bridge

════════════════════════════════════════════════════════════════
REQUIREMENTS FILES
════════════════════════════════════════════════════════════════

requirements.txt (no liboqs — for plain Python / WSL without Docker):
  cryptography>=42.0.0
  fastapi>=0.110.0
  uvicorn>=0.29.0
  pydantic>=2.0.0
  httpx>=0.27.0
  PyJWT>=2.8.0
  pytest>=8.0.0
  pytest-asyncio>=0.23.0

requirements-docker.txt (inside Docker — liboqs already in base image):
  liboqs-python>=0.14.1
  cryptography>=42.0.0
  fastapi>=0.110.0
  uvicorn>=0.29.0
  pydantic>=2.0.0
  httpx>=0.27.0
  PyJWT>=2.8.0
  pytest>=8.0.0
  pytest-asyncio>=0.23.0

════════════════════════════════════════════════════════════════
MAKEFILE
════════════════════════════════════════════════════════════════

.PHONY: setup test demo docker-build docker-demo clean

setup:
	bash setup.sh

test:
	pytest tests/ -v --tb=short

test-crypto:
	pytest tests/test_sss.py tests/test_lagrange.py tests/test_hkdf.py -v

demo:
	NODE_TRANSPORT=local python simulate/run_demo.py

docker-build:
	docker compose build

docker-demo:
	docker compose up --abort-on-container-exit demo

docker-test:
	docker compose run --rm demo pytest tests/ -v

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -name "*.pyc" -delete
	rm -rf data/

════════════════════════════════════════════════════════════════
SETUP.SH
════════════════════════════════════════════════════════════════

#!/bin/bash
# Run from WSL Ubuntu terminal
set -e

echo "[setup] Installing Python dependencies (no liboqs)..."
pip install -r requirements.txt

echo "[setup] Creating data directories..."
mkdir -p data
for i in 1 2 3 4 5; do mkdir -p data/node_$i; done

echo "[setup] Running crypto tests (no Docker needed)..."
pytest tests/test_sss.py tests/test_lagrange.py tests/test_hkdf.py \
       tests/test_keyfile.py tests/test_share_store.py tests/test_ledger.py \
       -v --tb=short

echo ""
echo "✅ Setup complete. Run 'make demo' to see the full demonstration."
echo "   For post-quantum mode: install Docker Desktop, then 'make docker-demo'"

════════════════════════════════════════════════════════════════
.github/workflows/ci.yml
════════════════════════════════════════════════════════════════

name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run tests (no liboqs — Ed25519 fallback)
        run: pytest tests/ -v --tb=short
        env:
          NODE_TRANSPORT: local

════════════════════════════════════════════════════════════════
README.md — MUST INCLUDE THESE SECTIONS
════════════════════════════════════════════════════════════════

# Decentralised IDP for ZTNA

## Quick Start (WSL / Linux)
  git clone ...
  cd decentralised-idp
  bash setup.sh
  make demo

## Docker Demo (Post-Quantum Mode)
  docker compose build
  make docker-demo

## Architecture
  Brief description of 4-layer architecture

## How It Works
  Registration flow (numbered steps)
  Authentication flow (numbered steps)

## Post-Quantum Security
  - What is broken in classical crypto (Ed25519, ECDH, Feldman VSS)
  - What we replaced and why (ML-DSA-65, ML-KEM-768, SHA-3 commitments)
  - What was already PQC-safe (SSS, AES-256, PBFT)
  - PQC_AVAILABLE flag explanation

## Attack Demonstrations
  Table: Attack | Defence | Expected Result

## Known Limitations
  1. Memory zeroing: Python GC not guaranteed — documented
  2. Feldman VSS simplified: hash commitments, not full cross-verification
  3. PBFT simplified: no view changes (future work)
  4. Single-machine ledger: simulates distributed ledger (future work)

## Team
  Ajay Koppaka - AM.SC.U4CYS23006
  Lokpradeep B - AM.SC.U4CYS23018
  Abhiram K.S.N.V. - AM.SC.U4CYS23026
  24CYS342 — Amrita Vishwa Vidyapeetham

════════════════════════════════════════════════════════════════
CRITICAL RULES FOR CLAUDE CODE
════════════════════════════════════════════════════════════════

1. BUILD IN THIS ORDER — each module depends on the ones before it:
   crypto/ → ledger/ → node/ → registration/ → authentication/ → api/ → simulate/ → tests/

2. NEVER import oqs outside crypto/pqc.py. Every other module uses
   crypto.pqc.sign(), crypto.pqc.verify(), crypto.pqc.generate_keypair() only.

3. NEVER use the random module for any cryptographic value.
   Always use secrets.token_bytes() or secrets.randbelow().

4. NEVER write S (identity secret) or private key bytes to any log,
   print statement, or file in plaintext.

5. ALL arithmetic in SSS and Lagrange MUST be mod P.
   Never perform SSS arithmetic without explicit % P.

6. The PQC fallback in crypto/pqc.py uses Ed25519.
   All tests MUST pass with PQC_AVAILABLE=False (no Docker needed for tests).
   Tests that specifically test PQC should be marked:
   @pytest.mark.skipif(not PQC_AVAILABLE, reason="liboqs not available")

7. Every function that touches S or private key bytes must zero them
   before returning, using: variable = 0; del variable
   This applies to: generate_shares(), register(), authenticate().

8. run_demo.py must work completely with NODE_TRANSPORT=local
   (no Docker, no network). Docker is only for the PQC mode.

9. Dockerfile base image is EXACTLY:
   openquantumsafe/liboqs-python:latest
   Do not try to build liboqs from source anywhere.

10. conftest.py must use pytest tmp_path fixture for all SQLite
    database paths so tests do not interfere with each other or
    with the data/ directory.
