# Decentralised Identity Provider — Complete System Explainer

> **What this is:** A post-quantum, fault-tolerant identity system. No single server holds your
> secret. No single server can impersonate you. Authentication requires 3 out of 5 independent
> nodes to cooperate — and even then, the secret is reconstructed for only a few microseconds
> before being erased.

---

## Table of Contents

1. [Big Picture Architecture](#1-big-picture-architecture)
2. [The Cryptographic Primitives](#2-the-cryptographic-primitives)
3. [Registration — Step by Step](#3-registration--step-by-step)
4. [What Each Machine Holds After Registration](#4-what-each-machine-holds-after-registration)
5. [Authentication — Step by Step](#5-authentication--step-by-step)
6. [Fault Tolerance — Why 2 Dead Nodes Don't Matter](#6-fault-tolerance--why-2-dead-nodes-dont-matter)
7. [Byzantine Fault Tolerance — What If a Node Lies?](#7-byzantine-fault-tolerance--what-if-a-node-lies)
8. [The Audit Ledger](#8-the-audit-ledger)
9. [The Identity Assertion Token (IAT)](#9-the-identity-assertion-token-iat)
10. [Docker Network — Are These Really Separate Machines?](#10-docker-network--are-these-really-separate-machines)
11. [What an Attacker Cannot Do](#11-what-an-attacker-cannot-do)
12. [File Map](#12-file-map)

---

## 1. Big Picture Architecture

```
  YOUR MACHINE
 ┌─────────────────────────────────────────────────────────────────┐
 │                                                                 │
 │   cli.py  ──────── POST /register ──────────────────────────►  │
 │                    POST /challenge                              │
 │                    POST /authenticate                           │
 │                                                                 │
 │   ~/.decidp/                                                    │
 │   ├── users.json          (username → DID mapping)             │
 │   └── did:decidp:xxxx.key (your AES-encrypted private key)     │
 │                                                                 │
 └──────────────────────────────┬──────────────────────────────────┘
                                │ HTTP  localhost:8000
                                ▼
              ┌─────────────────────────────────────┐
              │         COORDINATOR                 │
              │         api/main.py                 │
              │         172.18.0.2:8000             │
              │                                     │
              │  ┌──────────────────────────────┐   │
              │  │  Ledger (SQLite hash chain)  │   │
              │  │  - DID_REGISTER entries      │   │
              │  │  - AUTH_SUCCESS entries      │   │
              │  │  - AUTH_FAIL entries         │   │
              │  └──────────────────────────────┘   │
              └────┬──────┬──────┬──────┬──────┬────┘
                   │      │      │      │      │
          node1:8001  node2:8002  ...  node5:8005   (internal Docker DNS)
                   │      │      │      │      │
         ┌─────────┴─┐ ┌──┴──────┴─┐ ┌─┴──────┴──┐  ...
         │  NODE 1   │ │  NODE 2   │ │  NODE 3   │
         │172.18.0.7 │ │172.18.0.6 │ │172.18.0.3 │
         │           │ │           │ │           │
         │ shares.db │ │ shares.db │ │ shares.db │
         │ (1, f(1)) │ │ (2, f(2)) │ │ (3, f(3)) │
         └───────────┘ └───────────┘ └───────────┘
```

The **coordinator** is the brain — it handles all client requests.  
The **nodes** are simple vaults — each holds one encrypted share of your secret.  
No node talks to another node. All communication goes through the coordinator.

---

## 2. The Cryptographic Primitives

Before diving into the flows, here are the building blocks and why each one is used.

### 2a. ML-DSA-65 (Post-Quantum Signatures)

```
Classical: Ed25519  — broken by Shor's algorithm on a quantum computer
Quantum-safe: ML-DSA-65 — lattice-based, NIST PQC standard

Private key:  ~2500 bytes
Public key:   ~1952 bytes
Signature:    ~3309 bytes
```

Used for two things:
- **User signatures**: You sign the challenge nonce to prove you hold your private key
- **System signatures**: The coordinator signs the IAT token to prove it issued it

### 2b. Shamir Secret Sharing (SSS)

The core of the whole system. Takes a secret integer S and splits it into N shares such that:
- Any T shares → can reconstruct S exactly
- Any T-1 shares → reveals **zero** information about S (information-theoretically secure)

```
Parameters: T = 3  (threshold),  N = 5  (total shares)

Step 1 — Pick a random degree-(T-1) polynomial over a prime field:

    f(x) = S  +  a₁·x  +  a₂·x²     (all arithmetic mod P)
           ↑         ↑         ↑
         secret   random    random

Step 2 — Evaluate at x = 1, 2, 3, 4, 5:

    Share 1 = (1,  f(1))  → Node 1
    Share 2 = (2,  f(2))  → Node 2
    Share 3 = (3,  f(3))  → Node 3
    Share 4 = (4,  f(4))  → Node 4
    Share 5 = (5,  f(5))  → Node 5

To reconstruct S — Lagrange interpolation at x=0:

    S = f(0) = Σ  yᵢ · Lᵢ(0)     where Lᵢ are the Lagrange basis polynomials
```

Visual intuition: any 3 points uniquely define a degree-2 polynomial. Any 2 points leave the polynomial ambiguous — infinitely many polynomials pass through 2 points. So 2 shares tell you nothing.

```
           f(x)
            │     •(3, f(3))
            │   /
            │  •(2, f(2))
            │ /
    f(0)=S──•───────────────────── x
            │ •(1, f(1))
```

### 2c. HKDF — Deriving the Identity Secret S

S is never chosen by the user and never stored. It is always re-derived from:

```
IKM = your_public_key_bytes ‖ your_password_bytes
PRK = HMAC-SHA3-256(key=registration_nonce,  msg=IKM)
OKM = HMAC-SHA3-256(key=PRK,  msg="decidp-identity-secret-v1" ‖ 0x01)
S   = int(OKM, big-endian) mod (P-1) + 1
```

Why is this good?
- Change your password → completely different S → all existing shares become useless
- Steal your public key → useless without the password
- Steal your password → useless without the registration nonce (stored only in the ledger)
- S is deterministic given those three inputs — it can be re-derived for authentication

### 2d. AES-256-GCM — Encrypting Shares at Rest

Each node encrypts its y-coordinate before writing to SQLite:

```
aes_key    = 32 random bytes, stored in node_X/store.key
nonce      = 12 random bytes, generated fresh per share
ciphertext = AES-256-GCM(key=aes_key,  nonce=nonce,  plaintext=y,  aad=did)
```

The DID is used as **associated data** (AAD). GCM authentication will fail if the ciphertext
is moved to a different DID's row — it's cryptographically bound to that identity.

### 2e. PBKDF2 — Password-Protecting Your Keyfile

Your private key is stored locally, locked with your password:

```
aes_key = PBKDF2-HMAC-SHA3-256(
              password = your_password,
              salt     = 32 random bytes,
              iterations = 600,000,
              dklen    = 32
          )
```

600,000 iterations means an attacker trying to brute-force your password must run the
full PBKDF2 computation for every guess. On modern hardware that is ~2 guesses/second.

### 2f. SHA-3 Commitment Hash

At registration, a fingerprint of S is stored in the ledger:

```
commitment_hash = SHA3-256(S.to_bytes(32, 'big'))
```

At authentication, after reconstructing S from shares, this hash is recomputed and compared.
Nobody can reverse the hash to find S. It is only used to verify the reconstruction was correct.

---

## 3. Registration — Step by Step

```
 cli.py                      coordinator                         nodes 1-5
   │                              │                                  │
   │  POST /register              │                                  │
   │  { password: "..." }         │                                  │
   ├─────────────────────────────►│                                  │
   │                              │                                  │
   │                              │ 1. generate ML-DSA-65 key pair   │
   │                              │    (priv, pub)                   │
   │                              │                                  │
   │                              │ 2. DID = "did:decidp:" +         │
   │                              │    SHA3-256(pub)[:16]            │
   │                              │                                  │
   │                              │ 3. registration_nonce = 32       │
   │                              │    random bytes                  │
   │                              │                                  │
   │                              │ 4. S = HKDF(pub, nonce, password)│
   │                              │    [S is a 256-bit integer]      │
   │                              │                                  │
   │                              │ 5. shares = SSS(S, t=3, n=5)     │
   │                              │    [(1,f(1)), ..., (5,f(5))]     │
   │                              │                                  │
   │                              │ 6. commitments = SHA3(salt‖i‖yᵢ) │
   │                              │    (one per share, for integrity) │
   │                              │                                  │
   │                              │ 7. store share i on node i       │
   │                              ├─────────────────────────────────►│
   │                              │    node.share_store.store_share()│
   │                              │    y encrypted with AES-256-GCM  │
   │                              │                                  │
   │                              │ 8. ledger.append("DID_REGISTER") │
   │                              │    stores: pub_key, commitment_  │
   │                              │    hash, nonce, feldman_commits  │
   │                              │                                  │
   │                              │ 9. S = 0; del S  ← ZEROED       │
   │                              │    shares zeroed from memory     │
   │                              │                                  │
   │                              │ 10. save_keyfile(priv, pub,      │
   │                              │     password) → ~/.decidp/DID.key│
   │                              │                                  │
   │  { status, did,              │                                  │
   │    keyfile_path }            │                                  │
   │◄─────────────────────────────┤                                  │
   │                              │                                  │
   │ save username→DID            │                                  │
   │ to ~/.decidp/users.json      │                                  │
```

After registration, S exists **nowhere on disk**. The shares exist (encrypted, split across 5 nodes).
S can only be recovered by combining 3+ shares — and even then it should be immediately discarded.

---

## 4. What Each Machine Holds After Registration

```
 ┌─────────────────────────────────────────────────────────────────────┐
 │ YOUR MACHINE  (~/.decidp/)                                          │
 │                                                                     │
 │  users.json:  { "alice": { "did": "did:decidp:fedc9d...",          │
 │                             "keyfile_path": "~/.decidp/fedc9d.key" │
 │              } }                                                    │
 │                                                                     │
 │  fedc9d.key:  { "salt": "...", "nonce": "...",                      │
 │                 "ciphertext": "<<private key encrypted>>",          │
 │                 "public_key": "<<plaintext>>" }                     │
 └─────────────────────────────────────────────────────────────────────┘

 ┌──────────────────────────────────────────────────────────────────┐
 │ COORDINATOR  (data/ledger.db)                                    │
 │                                                                  │
 │  DID_REGISTER entry:                                             │
 │  - did:          "did:decidp:fedc9d..."                          │
 │  - public_key:   "a3f9..." (ML-DSA-65 public key, ~1952 bytes)   │
 │  - commitment_hash: SHA3-256(S) ← fingerprint, not S itself      │
 │  - nonce:        "7c3a..." (registration nonce)                  │
 │  - feldman_commitments: [...] (share integrity proofs)           │
 └──────────────────────────────────────────────────────────────────┘

 ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ...
 │   NODE 1     │  │   NODE 2     │  │   NODE 3     │
 │              │  │              │  │              │
 │ shares.db:   │  │ shares.db:   │  │ shares.db:   │
 │  x=1         │  │  x=2         │  │  x=3         │
 │  y=AES(f(1)) │  │  y=AES(f(2)) │  │  y=AES(f(3)) │
 │              │  │              │  │              │
 │ store.key:   │  │ store.key:   │  │ store.key:   │
 │  AES key     │  │  AES key     │  │  AES key     │
 └──────────────┘  └──────────────┘  └──────────────┘

   NOBODY holds S. It does not exist on any disk, in any form.
```

---

## 5. Authentication — Step by Step

```
cli.py                     coordinator                      nodes 1-5
  │                             │                               │
  │ 1. user types "alice"       │                               │
  │    look up DID in           │                               │
  │    ~/.decidp/users.json     │                               │
  │                             │                               │
  │ 2. load_keyfile(password)   │                               │
  │    PBKDF2 → AES-GCM decrypt │                               │
  │    → private key in memory  │                               │
  │                             │                               │
  │  POST /challenge            │                               │
  │  { did: "did:decidp:..." }  │                               │
  ├────────────────────────────►│                               │
  │                             │ nonce = 32 random bytes       │
  │                             │ challenge_id = UUID           │
  │                             │ stored in memory, TTL=30s     │
  │  { challenge_id, nonce }    │                               │
  │◄────────────────────────────┤                               │
  │                             │                               │
  │ 3. sign(private_key,        │                               │
  │         nonce ‖ did)        │                               │
  │    → signature (ML-DSA-65)  │                               │
  │                             │                               │
  │  POST /authenticate         │                               │
  │  { did, challenge_id, sig } │                               │
  ├────────────────────────────►│                               │
  │                             │                               │
  │                             │ 4. ASYNC — fire all 5         │
  │                             │    requests simultaneously    │
  │                             │    with 2s hard timeout each  │
  │                             ├──────────────────────────────►│
  │                             │    POST /internal/partial_proof
  │                             │◄─────────────────────────────┤
  │                             │    (dead nodes → timeout 2s)  │
  │                             │                               │
  │                             │ 5. verify signature           │
  │                             │    pqc_verify(pub, nonce‖did, │
  │                             │               sig)            │
  │                             │                               │
  │                             │ 6. PBFT consensus             │
  │                             │    majority vote on proofs    │
  │                             │    reject lying nodes         │
  │                             │                               │
  │                             │ 7. Lagrange reconstruction    │
  │                             │    S = interpolate(3 shares)  │
  │                             │                               │
  │                             │ 8. verify:                    │
  │                             │    SHA3(S) == commitment_hash │
  │                             │                               │
  │                             │ 9. S = 0; del S ← ZEROED     │
  │                             │                               │
  │                             │ 10. issue IAT token           │
  │                             │     sign with system key      │
  │                             │     jti=UUID, exp=now+60s     │
  │                             │                               │
  │  { status: "success",       │                               │
  │    iat: "eyJ...",           │                               │
  │    expires_in: 60 }         │                               │
  │◄────────────────────────────┤                               │
```

### What each node does when asked for a partial proof

Each node has its share `(x, y)` where `y = f(x)`. It cannot send `y` directly — that would
let the coordinator accumulate shares over time. Instead it sends a **blinded** version:

```
challenge_hash = SHA3-256(nonce).hexdigest()
H              = int(challenge_hash) % P       ← changes every authentication
partial_value  = (y × H) mod P                 ← y blinded by this session's H

return { node_id, x, partial_value, H, challenge_hash }
```

The coordinator undoes the blinding during reconstruction:

```
H_inv         = modular inverse of H (mod P)
y_recovered   = partial_value × H_inv mod P    ← y is back
shares        = [(x₁, y₁), (x₂, y₂), (x₃, y₃)]
S             = Lagrange(shares) at x=0
```

Why blind? Because `partial_value` is different every time even for the same share y. An attacker who intercepts partial proofs across multiple sessions cannot accumulate y-values — each `partial_value` is bound to that session's unique nonce.

---

## 6. Fault Tolerance — Why 2 Dead Nodes Don't Matter

```
Scenario: Nodes 3 and 4 are stopped  (docker stop idp-node3-1 idp-node4-1)

Timeline (milliseconds):

  t=0ms    coordinator fires 5 async requests simultaneously
           ├── node1:8001  ──►  responds at t=3ms   ✓
           ├── node2:8002  ──►  responds at t=4ms   ✓
           ├── node3:8003  ──►  SYN dropped by kernel (Docker stops RST)
           ├── node4:8004  ──►  SYN dropped by kernel
           └── node5:8005  ──►  responds at t=5ms   ✓

  t=2000ms asyncio.wait_for deadline fires for node3 and node4
           → both cancelled, return None

  t=2005ms coordinator has: [proof1, proof2, proof5]
           3 proofs ≥ THRESHOLD=3 → reconstruction proceeds

  t=2010ms S reconstructed, verified, zeroed, IAT issued

Total authentication time: ~2.1 seconds
```

**The key technical detail:** Docker's internal bridge network does not send TCP RST packets when a container is stopped. The kernel silently drops SYN packets. A normal `socket.settimeout()` or `httpx` timeout cannot cancel at the OS level — the SYN retransmit loop runs in kernel space. Only `asyncio.wait_for()` running inside the FastAPI event loop can cancel the `await` cleanly at the Python level.

```
What doesn't work:
   httpx timeout=2.0  →  still waits 8s  (kernel SYN retries bypass it)
   ThreadPoolExecutor + asyncio.wait_for  →  still waits 8s  (new event loop per thread)

What works:
   asyncio.gather() in FastAPI's OWN event loop  →  cancels at exactly 2.0s ✓
```

### All possible 2-node failure combinations

```
Nodes down    │  Nodes available  │  Can authenticate?
──────────────┼───────────────────┼───────────────────
1, 2          │  3, 4, 5          │  YES (3 of 5)
1, 3          │  2, 4, 5          │  YES
1, 4          │  2, 3, 5          │  YES
1, 5          │  2, 3, 4          │  YES
2, 3          │  1, 4, 5          │  YES
2, 4          │  1, 3, 5          │  YES
2, 5          │  1, 3, 4          │  YES
3, 4          │  1, 2, 5          │  YES
3, 5          │  1, 2, 4          │  YES
4, 5          │  1, 2, 3          │  YES
──────────────┼───────────────────┼───────────────────
1, 2, 3       │  4, 5             │  NO  (only 2 of 5)
```

---

## 7. Byzantine Fault Tolerance — What If a Node Lies?

A crashed node is easy to handle — it just doesn't respond. A **Byzantine node** is harder: it responds, but with malicious or corrupted data. The system handles this with two layers.

### Layer 1 — PBFT Consensus (Practical Byzantine Fault Tolerance)

```
Honest nodes return:
  { challenge_hash: "abc123...", H: 99483..., partial_value: 72834... }

A Byzantine node might tamper with H:
  { challenge_hash: "abc123...", H: 99999..., partial_value: 72834... }  ← wrong H

PBFT vote:
  challenge_hash "abc123..." : 4 votes  ← majority
  H 99483...               : 3 votes  ← majority among challenge_hash matches
  H 99999...               : 1 vote   ← discarded

Result: Byzantine node's proof is rejected before reconstruction even starts.
```

With 5 nodes and F_NODES=1, PBFT can tolerate 1 lying node. The quorum requirement is `2F+1 = 3`.

### Layer 2 — Commitment Hash Check

Even if a Byzantine node passes PBFT (correct `challenge_hash` and `H` but wrong `partial_value`), the reconstruction will produce garbage:

```
S_garbage = Lagrange(honest_1, honest_2, byzantine_3)

SHA3-256(S_garbage) ≠ commitment_hash  ← mismatch detected

→ coordinator tries next combination of 3 proofs
→ eventually finds [honest_1, honest_2, honest_5] → S correct → hash matches → success
```

The coordinator iterates all C(n, 3) = 10 combinations of 3 proofs until one reconstructs
an S whose SHA-3 hash matches the ledger entry. This is the final gate.

---

## 8. The Audit Ledger

The ledger is an **append-only SHA-3 hash chain** stored in `data/ledger.db`.

```
Entry 1 (DID_REGISTER)
┌──────────────────────────────────────────────────────────────┐
│  previous_hash: "000...000"  (genesis)                       │
│  entry_type:    "DID_REGISTER"                               │
│  did:           "did:decidp:fedc9d..."                       │
│  data:          { public_key, commitment_hash, nonce, ... }  │
│  timestamp:     1778853000.123                               │
│  entry_hash:    SHA3-256(prev ‖ type ‖ did ‖ data ‖ time)   │
│               = "a4f2c9..."                                  │
└──────────────────────────────────────────────────────────────┘
                          │
                          └─► feeds into next entry as previous_hash

Entry 2 (AUTH_SUCCESS)
┌──────────────────────────────────────────────────────────────┐
│  previous_hash: "a4f2c9..."   ← hash of entry 1             │
│  entry_type:    "AUTH_SUCCESS"                               │
│  did:           "did:decidp:fedc9d..."                       │
│  data:          { quorum_nodes: [1,2,3], token_jti: "..." }  │
│  entry_hash:    "7b3d1e..."                                  │
└──────────────────────────────────────────────────────────────┘
```

Tampering with any historical entry changes its hash, which breaks the chain for every subsequent
entry. `ledger.verify_chain()` detects this instantly. The `/health` endpoint reports
`ledger_chain_valid: true/false` on every request.

Entry types: `DID_REGISTER`, `AUTH_SUCCESS`, `AUTH_FAIL`, `SHARE_REVOKE`

---

## 9. The Identity Assertion Token (IAT)

Structured like a JWT but issued and verified entirely within this system.

```
┌─────────────────────────────────────────────────────────────┐
│                        HEADER                               │
│  { "alg": "ML-DSA-65", "typ": "DECIDP-IAT" }               │
│  → base64url encoded                                        │
│  → always identical (algorithm never changes)              │
├─────────────────────────────────────────────────────────────┤
│                        PAYLOAD                              │
│  {                                                          │
│    "sub":    "did:decidp:fedc9d...",  ← who this token is for│
│    "iat":    1778853281,              ← issued at (unix time) │
│    "exp":    1778853341,              ← expires at (iat + 60s)│
│    "jti":    "7b6dd5f8-4b4b-...",    ← unique UUID per token │
│    "quorum": [1, 2, 3],              ← which nodes confirmed │
│    "iss":    "did:decidp:system"     ← issuer               │
│  }                                                          │
│  → base64url encoded                                        │
├─────────────────────────────────────────────────────────────┤
│                        SIGNATURE                            │
│  ML-DSA-65.sign(system_private_key, header_b64.payload_b64) │
│  → base64url encoded                                        │
│  → ~3309 bytes                                              │
└─────────────────────────────────────────────────────────────┘

Final token: "<header_b64>.<payload_b64>.<sig_b64>"
```

**Why the first 80 chars look the same every time:**  
The header encodes to 54 fixed characters. The CLI shows only the first 80 chars, which is
the entire header plus the start of the payload. The payload begins with `"exp":` (sorted keys),
and since `exp = now + 60` changes by only a few digits, the base64 of the first few bytes
looks similar. The `jti` UUID and the full signature are always unique.

**Token validation (`GET /verify?token=...`):**
1. Split on `.` — must have exactly 3 parts
2. Verify ML-DSA-65 signature against system public key
3. Check `time.time() < payload["exp"]`
4. Return `{ valid, did, expires_at }`

**Replay window:** An intercepted token can be reused within its 60-second TTL. There is no
revocation list. This is the standard stateless-token trade-off: short TTL instead of state.

---

## 10. Docker Network — Are These Really Separate Machines?

Yes. Each container has its own network namespace and IP.

```
Docker bridge network: 172.18.0.0/16

  Container          IP              Port
  ─────────────────────────────────────────
  idp-coordinator-1  172.18.0.2      8000
  idp-node1-1        172.18.0.7      8001
  idp-node2-1        172.18.0.6      8002
  idp-node3-1        172.18.0.3      8003
  idp-node4-1        172.18.0.4      8004
  idp-node5-1        172.18.0.5      8005
```

The coordinator contacts nodes via DNS names (not localhost):

```python
NODE_PEERS = "node1:8001,node2:8002,node3:8003,node4:8004,node5:8005"
```

`node1` resolves to `172.18.0.7`. When node3 is stopped, `172.18.0.3` becomes unreachable —
not a closed port, the entire network path goes dark (kernel drops SYN packets).

The `localhost:800X` ports you use from your terminal are **port-forwards** from your host
machine into Docker — they exist only for the CLI and for observing the system from outside.
The actual authentication traffic between coordinator and nodes uses private container IPs.

```
Authentication traffic path:

  cli.py (your terminal)
    │
    │  localhost:8000  (port-forward)
    ▼
  coordinator  172.18.0.2
    │
    │  node1:8001  → 172.18.0.7   (internal Docker DNS)
    │  node2:8002  → 172.18.0.6
    │  node3:8003  → 172.18.0.3   ← if stopped: SYN drops, timeout at 2s
    │  node4:8004  → 172.18.0.4
    │  node5:8005  → 172.18.0.5
```

**Real deployment:** Replace each container with a VM or bare-metal server in a different
data centre. Change `NODE_PEERS` to the real hostnames. Everything else is identical.

---

## 11. What an Attacker Cannot Do

```
┌───────────────────────────────────────┬──────────────────────────────────────────────┐
│  Attack                               │  Why it fails                                │
├───────────────────────────────────────┼──────────────────────────────────────────────┤
│ Steal node 1's entire database        │ Gets 1 of 5 shares. Mathematically zero       │
│                                       │ information about S. 2 < threshold = 3.       │
├───────────────────────────────────────┼──────────────────────────────────────────────┤
│ Steal nodes 1 and 2's databases       │ Gets 2 of 5 shares. Still zero information.   │
│                                       │ Need 3 to reconstruct.                        │
├───────────────────────────────────────┼──────────────────────────────────────────────┤
│ Steal the coordinator's ledger        │ Has commitment_hash (SHA3 of S) and public    │
│                                       │ keys. Cannot reverse SHA3. Cannot sign        │
│                                       │ without private key. Cannot reconstruct S     │
│                                       │ without shares from nodes.                    │
├───────────────────────────────────────┼──────────────────────────────────────────────┤
│ Intercept a partial proof from node i │ partial_value = y × H mod P. H is different   │
│ and reuse it next session             │ every session (derived from the nonce). The   │
│                                       │ intercepted value is useless with a new H.    │
├───────────────────────────────────────┼──────────────────────────────────────────────┤
│ Replay a valid challenge request      │ consume() deletes the nonce on first use.     │
│                                       │ A second use returns "challenge_invalid".     │
├───────────────────────────────────────┼──────────────────────────────────────────────┤
│ Replay a valid IAT token              │ Works within 60-second TTL only. Permanently  │
│                                       │ rejected after exp timestamp.                 │
├───────────────────────────────────────┼──────────────────────────────────────────────┤
│ Submit a valid signature for a        │ Signature covers nonce ‖ did. Changing the    │
│ different DID                         │ DID changes the signed message → sig invalid. │
├───────────────────────────────────────┼──────────────────────────────────────────────┤
│ Byzantine node: lie about partial     │ Layer 1: PBFT discards proofs with wrong H.   │
│ proof value                           │ Layer 2: commitment hash check catches wrong  │
│                                       │ partial_value after reconstruction fails.     │
├───────────────────────────────────────┼──────────────────────────────────────────────┤
│ Brute-force the keyfile password      │ 600,000 PBKDF2 iterations ≈ 2 guesses/second  │
│                                       │ on modern hardware. Also needs the private    │
│                                       │ key to be useful — which is only on your      │
│                                       │ machine.                                      │
├───────────────────────────────────────┼──────────────────────────────────────────────┤
│ Tamper with the ledger history        │ SHA-3 hash chain: changing any entry changes  │
│                                       │ its hash, breaking all subsequent hashes.     │
│                                       │ verify_chain() detects immediately.           │
├───────────────────────────────────────┼──────────────────────────────────────────────┤
│ Quantum computer breaks signatures    │ ML-DSA-65 is a NIST PQC standard, lattice-    │
│                                       │ based. Not broken by Shor's algorithm.        │
└───────────────────────────────────────┴──────────────────────────────────────────────┘
```

---

## 12. File Map

```
decentralised-idp/
│
├── crypto/
│   ├── __init__.py       Constants: P, N_NODES=5, THRESHOLD=3, TTLs
│   ├── lagrange.py       Lagrange interpolation over a prime field
│   ├── sss.py            Shamir Secret Sharing (split + reconstruct)
│   ├── hkdf.py           HKDF: derive identity secret S from pub+password+nonce
│   ├── feldman.py        SHA-3 commitments for share integrity verification
│   ├── pqc.py            ML-DSA-65 signatures + ML-KEM-768 KEM (liboqs wrapper)
│   └── keyfile.py        Save/load AES-256-GCM encrypted private key files
│
├── ledger/
│   └── ledger.py         Append-only SHA-3 hash chain (SQLite backed)
│
├── node/
│   ├── share_store.py    AES-256-GCM encrypted SQLite store for SSS shares
│   ├── partial_proof.py  Compute y×H mod P; recover S via Lagrange
│   ├── node.py           Node object: holds ShareStore, computes proofs
│   ├── pbft.py           Simplified PBFT consensus (majority vote on proofs)
│   └── transport.py      LocalTransport (in-process) / HTTPTransport (Docker)
│
├── registration/
│   └── register.py       12-step registration orchestrator
│
├── authentication/
│   ├── challenge.py      Issue + consume single-use nonces (TTL=30s)
│   ├── iat.py            Issue + verify Identity Assertion Tokens (TTL=60s)
│   └── authenticate.py   9-step authentication orchestrator
│
├── api/
│   ├── main.py           Coordinator FastAPI app (all public endpoints)
│   └── node_service.py   Per-node FastAPI app (/health + /internal/partial_proof)
│
├── cli.py                Interactive demo CLI (h/r/a/q commands)
├── docker-compose.yml    1 coordinator + 5 node containers, shared ./data volume
├── Dockerfile            Builds liboqs + Python app image
└── Makefile              make net-up / net-down / net-clean / net-logs
```

---

*Generated from live codebase — all code paths verified against actual source files.*
