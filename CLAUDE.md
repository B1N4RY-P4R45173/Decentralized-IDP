# Project: Decentralised IDP for ZTNA

## MANDATORY — Read before doing anything

This file contains standing instructions that apply to
every single action in this project. Never override these.

---

## Build Order — STRICT

Build modules in EXACTLY this order. Do not jump ahead.
Complete and test each module before moving to the next.

1.  crypto/__init__.py          (constants only)
2.  crypto/lagrange.py          (test immediately after)
3.  crypto/sss.py               (test immediately after)
4.  crypto/hkdf.py              (test immediately after)
5.  crypto/feldman.py           (test immediately after)
6.  crypto/pqc.py               (test immediately after)
7.  crypto/keyfile.py           (test immediately after)
8.  ledger/ledger.py            (test immediately after)
9.  node/share_store.py         (test immediately after)
10. node/partial_proof.py       (test immediately after)
11. node/transport.py
12. node/node.py
13. node/pbft.py                (test immediately after)
14. registration/register.py    (test immediately after)
15. authentication/challenge.py
16. authentication/iat.py
17. authentication/authenticate.py (test immediately after)
18. api/main.py
19. simulate/attacks.py
20. simulate/run_demo.py
21. tests/conftest.py
22. All remaining test files
23. Dockerfile
24. docker-compose.yml
25. Makefile + setup.sh + .github/workflows/ci.yml + README.md

---

## After Writing Each File

After writing EVERY file:
1. Run it or its test immediately
2. Fix any errors before moving on
3. Never move to the next module if the current one has a failing test

---

## Absolute Rules

- NEVER use the `random` module for cryptographic values.
  Always use `secrets.token_bytes()` or `secrets.randbelow()`.

- NEVER print, log, or write S (identity secret) or private
  key bytes in plaintext anywhere.

- ALL SSS and Lagrange arithmetic MUST use explicit `% P`
  on every operation.

- NEVER import oqs outside crypto/pqc.py.

- NEVER try to build liboqs from source.
  Docker base image is: openquantumsafe/liboqs-python:latest

- ALL tests must pass with PQC_AVAILABLE=False (no Docker needed).

- ALL SQLite paths in tests use pytest tmp_path fixture.

- Zero S and private key bytes before every return:
      variable = 0
      del variable

---

## Python Version

3.12.3 — use match statements and X | Y union types freely.

---

## Environment

WSL2 Ubuntu on Windows.
NODE_TRANSPORT=local for all tests and demo (no Docker needed).
Docker only needed for PQC (ML-DSA-65 / ML-KEM-768) mode.

---

## PQC Algorithm Name Strings (exact, case-sensitive)

Signatures : "ML-DSA-65"
KEM        : "ML-KEM-768"

---

## If You Are Unsure About Anything

Stop and ask before writing code.
Do not guess. Do not hallucinate library APIs.
Verify every external library call against what you know is
correct for Python 3.12 and the installed package versions.

---

## Package Versions (installed, verified)

cryptography  >= 42.0.0
fastapi       >= 0.110.0
uvicorn       >= 0.29.0
pydantic      >= 2.0.0
httpx         >= 0.27.0
PyJWT         >= 2.8.0
pytest        >= 8.0.0
pytest-asyncio >= 0.23.0
liboqs-python  0.14.1 (Docker only)

