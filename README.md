# Decentralised IDP for ZTNA

A post-quantum decentralised identity provider for Zero Trust Network Access, using Shamir's Secret Sharing (SSS), Byzantine Fault Tolerant (BFT) consensus, and ML-DSA-65 / ML-KEM-768 cryptography via liboqs.

---

## Quick Start (WSL / Linux)

```bash
git clone <repo-url>
cd decentralised-idp
bash setup.sh
make demo
```

`setup.sh` installs Python dependencies (no Docker required), creates data directories, and runs the core crypto tests. `make demo` launches the full coloured terminal demonstration.

---

## Docker Demo (Post-Quantum Mode)

Requires Docker Desktop with WSL2 integration enabled.

```bash
docker compose build
make docker-demo
```

The Docker build uses `openquantumsafe/liboqs-python:latest` as the base image, which ships a pre-built liboqs C library. This enables ML-DSA-65 signatures and ML-KEM-768 key encapsulation instead of the Ed25519 fallback.

To run the full test suite inside Docker (with PQC):

```bash
make docker-test
```

---

## Architecture

The system is organised into four layers:

```
┌────────────────────────────────────────────┐
│  API layer        api/main.py              │  FastAPI — REST endpoints
├────────────────────────────────────────────┤
│  Service layer    registration/ auth/      │  Registration & authentication logic
├────────────────────────────────────────────┤
│  Node layer       node/                    │  5 BFT nodes, SSS shares, PBFT
├────────────────────────────────────────────┤
│  Crypto layer     crypto/                  │  SSS, Lagrange, HKDF, PQC, keyfile
└────────────────────────────────────────────┘
            ledger/                            Hash-chain ledger (SQLite)
```

**5-node network** — `N=5`, fault-tolerance `f=1`, quorum `2f+1=3`. One Byzantine or crashed node cannot affect correctness; two offline nodes cause quorum failure by design.

---

## How It Works

### Registration flow

1. Generate ML-DSA-65 keypair `(priv, pub)` for the user.
2. Derive DID: `"did:decidp:" + SHA3-256(pub)[:16]`.
3. Generate a 32-byte random `registration_nonce`.
4. Derive identity secret: `S = HKDF-SHA3-256(pub, nonce, password)`, where `S ∈ [1, P-1]`.
5. Split S into 5 shares using a degree-2 polynomial over GF(P): `shares = SSS(S, t=3, n=5)`.
6. Compute Feldman-style SHA-3 commitments for each share value.
7. Store one share per node (AES-256-GCM encrypted in SQLite, AAD = DID).
8. Append `DID_REGISTER` entry to the hash-chain ledger (commitment hash, nonce, public key, Feldman commitments).
9. Zero `S` and all share values in memory.
10. Save the user's private key to `~/.decidp/<did>.key` (AES-256-GCM, PBKDF2-SHA3 key derivation, 600 000 iterations).

### Authentication flow

1. User requests a challenge nonce (32 random bytes, 30 s TTL, single-use).
2. User signs `nonce ∥ DID` with their ML-DSA-65 private key.
3. Server verifies the signature against the public key on the ledger.
4. Server collects partial proofs from all 5 nodes: `partial_i = (share_i.y × H) mod P`, where `H = SHA3-256(nonce)` interpreted as a field element.
5. **PBFT consensus** — proofs with mismatched `challenge_hash` or `H` are discarded; quorum requires ≥ 3 matching proofs.
6. **Byzantine-tolerant reconstruction** — all C(n_clean, 3) subsets of PBFT-accepted proofs are tried via Lagrange interpolation until one reconstructs an S whose SHA-3 commitment hash matches the ledger.
7. S is zeroed immediately after the commitment check.
8. Server issues a signed Identity Assertion Token (IAT) — a JWT-structured token signed with the system ML-DSA-65 key, TTL 60 s.

---

## Post-Quantum Security

### What classical cryptography gets broken by Shor's algorithm

| Algorithm | Classical purpose | Quantum attack |
|-----------|------------------|----------------|
| Ed25519 | Signatures | Shor's (ECDLP) |
| ECDH / X25519 | Key agreement | Shor's (ECDLP) |
| Feldman VSS (g^x mod p) | Share verification | Shor's (DLP) |

### What we replaced and why

| Classical | Post-quantum replacement | Why |
|-----------|--------------------------|-----|
| Ed25519 signatures | **ML-DSA-65** (CRYSTALS-Dilithium) | NIST PQC standard; lattice-based, immune to Shor's |
| ECDH share delivery | **ML-KEM-768** (CRYSTALS-Kyber) | NIST PQC standard; lattice-based KEM |
| Feldman g^x commitments | **SHA-3 hash commitments** | SHA-3 is Grover-resistant; no discrete-log assumption |

### What was already post-quantum safe

- **Shamir's Secret Sharing** — pure arithmetic over GF(P); no hardness assumption beyond information theory (with t−1 shares, S is perfectly hidden).
- **AES-256-GCM** — Grover's algorithm halves effective key length to 128 bits, still secure.
- **PBFT consensus** — protocol logic; no cryptographic hardness assumption.
- **SHA-3 hash chain** — collision-resistant under Grover with 256-bit output.

### `PQC_AVAILABLE` flag

`crypto/pqc.py` sets `PQC_AVAILABLE = True` only when `import oqs` succeeds (requires the liboqs C library, available in Docker). When `False`, the module falls back to Ed25519 and emits a warning. All 101 tests pass with `PQC_AVAILABLE = False` — no Docker required for testing.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/register` | Register new user; returns DID and keyfile path |
| `POST` | `/challenge` | Issue a single-use challenge nonce for a DID |
| `POST` | `/authenticate` | Verify signed challenge; return IAT on success |
| `GET`  | `/verify?token=…` | Verify an IAT; return `{valid, did, expires_at}` |
| `GET`  | `/health` | Node status, PQC flag, ledger chain validity |

---

## Attack Demonstrations

Run `make demo` to see all five attacks live in the terminal.

| Attack | Defence | Expected result |
|--------|---------|-----------------|
| Node crash (1 node offline) | BFT fault tolerance (f=1) | BLOCKED — 4 remaining nodes form quorum |
| Byzantine wrong proof | PBFT outlier detection | BLOCKED — Byzantine proof discarded, 4 honest nodes reconstruct S |
| 2-node share theft | SSS threshold (t=3) | BLOCKED — 2 shares are information-theoretically zero-knowledge |
| Replay intercepted auth | Single-use challenge nonces | BLOCKED — consumed nonce rejected immediately |
| Wrong password keyfile | AES-256-GCM + PBKDF2 | BLOCKED — GCM authentication tag fails |

---

## Running Tests

```bash
# All tests (no Docker)
make test

# Crypto-only subset
make test-crypto

# Inside Docker (with PQC)
make docker-test
```

101 tests pass, 1 skipped (`test_pqc_sign_size` — requires liboqs).

---

## Project Structure

```
decentralised-idp/
├── crypto/          SSS, Lagrange, HKDF, Feldman, PQC wrapper, keyfile
├── node/            Node, ShareStore, partial proofs, PBFT, transport
├── ledger/          SHA-3 hash-chain ledger (SQLite)
├── registration/    RegistrationService
├── authentication/  ChallengeManager, IAT, AuthenticationService
├── api/             FastAPI application
├── simulate/        Attack classes and live demo script
├── tests/           101 pytest tests
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── setup.sh
└── requirements.txt
```

---

## Known Limitations

1. **Memory zeroing** — Python's garbage collector does not guarantee immediate erasure of zeroed variables. `S = 0; del S` reduces the window of exposure but is not a hardware-level secure erase. A production system would use `ctypes` or a Rust extension for guaranteed zeroing.

2. **Simplified Feldman VSS** — Share commitments use `SHA3-256(salt ∥ index ∥ y)` per share. This proves each node holds the correct y-value, but does not implement full polynomial cross-verification (each node checking all other nodes' shares against the committed polynomial). Full cross-verification is left as future work.

3. **Simplified PBFT** — The consensus protocol implements the prepare/commit phases but omits view-change (leader re-election on timeout). A crashed primary would stall authentication until restarted. Full Castro-Liskov PBFT with view changes is future work.

4. **Single-machine ledger** — The `Ledger` class uses a local SQLite file as a simulated distributed ledger. In production, this would be replaced by a Byzantine-fault-tolerant distributed log (e.g., Hyperledger Fabric or a custom BFT state machine). The hash-chain structure is already production-ready; only the storage backend needs to be distributed.

---

## Team

| Name | Roll Number |
|------|-------------|
| Ajay Koppaka | AM.SC.U4CYS23006 |
| Lokpradeep B | AM.SC.U4CYS23018 |
| Abhiram K.S.N.V. | AM.SC.U4CYS23026 |

**24CYS342 — Amrita Vishwa Vidyapeetham**
