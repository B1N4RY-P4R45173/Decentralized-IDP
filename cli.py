#!/usr/bin/env python3
"""
Manual demo CLI — Decentralised IDP
Talks to the coordinator at localhost:8000.
Checks each node directly at localhost:8001-8005.

Usage:
    python cli.py

Commands (interactive):
    h  — show node health
    r  — register a user  (asks for username + password)
    a  — authenticate     (asks for username + password)
    q  — quit
"""

import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import httpx

from crypto.keyfile import load_keyfile
from crypto.pqc import sign as pqc_sign

COORDINATOR = "http://localhost:8000"
NODE_URLS   = {i: f"http://localhost:{8000 + i}" for i in range(1, 6)}
THRESHOLD   = 3
TIMEOUT     = 60.0

# Local file that maps username → {did, keyfile_path}
USERS_FILE  = os.path.expanduser("~/.decidp/users.json")

RESET  = "\033[0m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"


# ── Local user registry ───────────────────────────────────────────────────────

def _load_users() -> dict:
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE) as f:
            return json.load(f)
    return {}


def _save_users(users: dict) -> None:
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


# ── Helpers ───────────────────────────────────────────────────────────────────

def banner(title: str) -> None:
    print(f"\n{BOLD}{BLUE}{'═' * 60}{RESET}")
    print(f"{BOLD}{BLUE}  {title}{RESET}")
    print(f"{BOLD}{BLUE}{'═' * 60}{RESET}\n")


def node_status() -> dict[int, bool]:
    status = {}
    for nid, url in NODE_URLS.items():
        try:
            r = httpx.get(f"{url}/health", timeout=2.0)
            status[nid] = r.status_code == 200
        except Exception:
            status[nid] = False
    return status


def _decode_iat_payload(token: str) -> dict:
    try:
        _, payload_b64, _ = token.split(".")
        payload_b64 += "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:
        return {}


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_health() -> None:
    banner("NODE HEALTH")
    status = node_status()
    online = sum(v for v in status.values())

    for nid, up in status.items():
        color = GREEN if up else RED
        label = "ONLINE  ✓" if up else "OFFLINE ✗"
        print(f"  {color}Node {nid}  {label}   localhost:{8000 + nid}{RESET}")

    print()
    if online >= THRESHOLD:
        print(f"  {GREEN}{online}/5 nodes live — threshold {THRESHOLD} met ✓{RESET}")
    else:
        print(f"  {RED}{online}/5 nodes live — below threshold {THRESHOLD} — "
              f"authentication will fail ✗{RESET}")


def cmd_register() -> None:
    banner("REGISTER USER")
    print(f"  {DIM}POST {COORDINATOR}/register{RESET}\n")

    username = input(f"  {CYAN}Username: {RESET}").strip()
    if not username:
        print(f"  {RED}Username cannot be empty.{RESET}")
        return

    password = input(f"  {CYAN}Password: {RESET}").strip()
    if not password:
        print(f"  {RED}Password cannot be empty.{RESET}")
        return

    # Check if username already registered locally
    users = _load_users()
    if username in users:
        print(f"  {YELLOW}Username '{username}' already registered locally.{RESET}")
        print(f"  {YELLOW}Registering again will create a NEW identity.{RESET}")
        confirm = input(f"  {CYAN}Continue? (y/n): {RESET}").strip().lower()
        if confirm != "y":
            return

    try:
        r = httpx.post(
            f"{COORDINATOR}/register",
            json={"password": password},
            timeout=TIMEOUT,
        )
        data = r.json()
    except Exception as exc:
        print(f"  {RED}Request failed: {exc}{RESET}")
        return

    if data.get("status") == "success":
        did          = data["did"]
        keyfile_path = os.path.expanduser(data["keyfile_path"])

        # Save username → DID mapping locally
        users[username] = {"did": did, "keyfile_path": keyfile_path}
        _save_users(users)

        print(f"  {GREEN}Username: {username}{RESET}")
        print(f"  {GREEN}DID:      {did}{RESET}")
        print(f"  {GREEN}Keyfile:  {keyfile_path}{RESET}")
        print(f"  {GREEN}Secret S split into 5 shares (Shamir, threshold = 3){RESET}")
        for i in range(1, 6):
            print(f"  {GREEN}  Share {i} → Node {i} ✓{RESET}")
        print(f"  {GREEN}S zeroed from coordinator memory ✓{RESET}")
    else:
        print(f"  {RED}Registration failed: {data}{RESET}")


def cmd_authenticate() -> None:
    banner("AUTHENTICATE")

    username = input(f"  {CYAN}Username: {RESET}").strip()
    if not username:
        print(f"  {RED}Username cannot be empty.{RESET}")
        return

    password = input(f"  {CYAN}Password: {RESET}").strip()
    if not password:
        print(f"  {RED}Password cannot be empty.{RESET}")
        return

    # Look up DID and keyfile from local registry
    users = _load_users()
    if username not in users:
        print(f"  {RED}Unknown username '{username}'. Run 'r' to register first.{RESET}")
        return

    did          = users[username]["did"]
    keyfile_path = users[username]["keyfile_path"]
    print(f"  {DIM}DID: {did}{RESET}")

    # Show live node status
    status      = node_status()
    online_ids  = [nid for nid, up in status.items() if up]
    offline_ids = [nid for nid, up in status.items() if not up]
    print()
    print(f"  {GREEN}Online nodes:  {online_ids}{RESET}")
    if offline_ids:
        print(f"  {RED}Offline nodes: {offline_ids}{RESET}")

    # Load keyfile
    try:
        priv, _ = load_keyfile(keyfile_path, password)
    except FileNotFoundError:
        print(f"  {RED}Keyfile not found: {keyfile_path}{RESET}")
        return
    except ValueError:
        print(f"  {RED}Wrong password — keyfile decryption failed ✗{RESET}")
        return

    # Get challenge
    try:
        r  = httpx.post(f"{COORDINATOR}/challenge", json={"did": did}, timeout=5.0)
        ch = r.json()
    except Exception as exc:
        print(f"  {RED}Challenge request failed: {exc}{RESET}")
        return

    nonce_bytes = bytes.fromhex(ch["nonce"])
    print(f"\n  {CYAN}Challenge:  {ch['challenge_id'][:24]}...{RESET}")

    # Sign nonce + DID
    sig     = pqc_sign(priv, nonce_bytes + did.encode("utf-8"))
    sig_hex = sig.hex()
    print(f"  {CYAN}Signature:  {sig_hex[:24]}...{RESET}")
    print(f"  {DIM}Contacting {len(online_ids)} live node(s)...{RESET}")

    # Submit
    try:
        r = httpx.post(
            f"{COORDINATOR}/authenticate",
            json={
                "did":          did,
                "challenge_id": ch["challenge_id"],
                "signature":    sig_hex,
            },
            timeout=TIMEOUT,
        )
        data = r.json()
    except Exception as exc:
        print(f"  {RED}Authenticate request failed: {exc}{RESET}")
        return

    print()
    if data.get("status") == "success":
        payload = _decode_iat_payload(data["iat"])
        quorum  = payload.get("quorum", [])
        print(f"  {GREEN}{BOLD}Authentication SUCCEEDED ✓{RESET}")
        print(f"  {GREEN}Quorum nodes used:  {quorum}{RESET}")
        print(f"  {GREEN}Token expires in:   {data['expires_in']}s{RESET}")
        print(f"  {DIM}IAT (first 80 chars): {data['iat'][:80]}...{RESET}")
    else:
        reason = data.get("reason", "unknown")
        print(f"  {RED}{BOLD}Authentication FAILED ✗{RESET}")
        print(f"  {RED}Reason: {reason}{RESET}")
        if len(online_ids) < THRESHOLD:
            print(f"  {YELLOW}Only {len(online_ids)} node(s) online — "
                  f"need at least {THRESHOLD}.{RESET}")


# ── Main loop ─────────────────────────────────────────────────────────────────

def main() -> None:
    banner("Decentralised IDP — Manual Demo")
    print(f"  Coordinator:  {BOLD}{COORDINATOR}{RESET}")
    print(f"  Node ports:   {BOLD}localhost:8001  →  localhost:8005{RESET}")
    print()
    print(f"  {YELLOW}Open a second terminal to kill / restart individual nodes:{RESET}")
    print(f"  {YELLOW}  docker stop  idp-node3-1{RESET}")
    print(f"  {YELLOW}  docker stop  idp-node4-1{RESET}")
    print(f"  {YELLOW}  docker start idp-node3-1{RESET}")
    print()
    print(f"  {DIM}Run 'docker ps' to confirm container names.{RESET}")
    print(f"  {DIM}Run 'docker logs -f idp-coordinator-1' to see coordinator output.{RESET}")

    while True:
        print(f"\n{BOLD}Commands:{RESET}  "
              f"{CYAN}h{RESET}ealth   "
              f"{CYAN}r{RESET}egister   "
              f"{CYAN}a{RESET}uth   "
              f"{CYAN}q{RESET}uit")
        try:
            cmd = input(f"{BOLD}> {RESET}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            break

        match cmd:
            case "h" | "health":
                cmd_health()
            case "r" | "register":
                cmd_register()
            case "a" | "auth" | "authenticate":
                cmd_authenticate()
            case "q" | "quit" | "exit":
                print("Bye.")
                break
            case "":
                pass
            case _:
                print(f"  {YELLOW}Unknown command. Use h, r, a, or q.{RESET}")


if __name__ == "__main__":
    main()
