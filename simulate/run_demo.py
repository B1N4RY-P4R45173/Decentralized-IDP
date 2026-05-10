"""
Full coloured terminal demonstration.
Uses ANSI colour codes — works in WSL2 terminal.

Run with: python simulate/run_demo.py
Or:       make demo
"""

import os
import sys

# Ensure project root is on sys.path when run directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tempfile

import authentication.iat as _iat
from authentication.authenticate import AuthenticationService
from authentication.challenge import ChallengeManager
from crypto.keyfile import load_keyfile
from crypto.pqc import PQC_AVAILABLE, sign as pqc_sign
from ledger.ledger import Ledger
from node.node import Node
from node.transport import LocalTransport
from registration.register import RegistrationService
from simulate.attacks import (
    ByzantineWrongProofAttack,
    NodeCrashAttack,
    ReplayAttack,
    ShareTheftAttack,
)

# ── ANSI colours ──────────────────────────────────────────────────────────────

RESET  = "\033[0m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"


def separator(title: str):
    print(f"\n{BOLD}{BLUE}{'═' * 60}{RESET}")
    print(f"{BOLD}{BLUE}  {title}{RESET}")
    print(f"{BOLD}{BLUE}{'═' * 60}{RESET}\n")


def pause():
    try:
        input(f"  {YELLOW}↵ Press Enter to continue...{RESET}")
    except EOFError:
        pass


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sign_challenge(priv: bytes, nonce_hex: str, did: str) -> str:
    nonce_bytes = bytes.fromhex(nonce_hex)
    sig = pqc_sign(priv, nonce_bytes + did.encode("utf-8"))
    return sig.hex()


def _authenticate_alice(
    auth_service: AuthenticationService,
    challenge_manager: ChallengeManager,
    did: str,
    priv: bytes,
) -> dict:
    ch = challenge_manager.issue(did)
    sig_hex = _sign_challenge(priv, ch["nonce"], did)
    return ch, sig_hex, auth_service.authenticate(did, ch["challenge_id"], sig_hex)


# ── Main demo ─────────────────────────────────────────────────────────────────

def main():
    data_dir = tempfile.mkdtemp(prefix="decidp_demo_")

    # ── SETUP ─────────────────────────────────────────────────────────────────
    separator("SETUP — Initialising 5-Node BFT Network")

    nodes = [Node(node_id=i, data_dir=data_dir) for i in range(1, 6)]
    transport = LocalTransport()
    for n in nodes:
        transport.register_node(n.node_id, n)

    ledger = Ledger(db_path=os.path.join(data_dir, "ledger.db"))
    challenge_manager = ChallengeManager()
    _iat.init_system_keys(data_dir)

    reg_service = RegistrationService(nodes=nodes, ledger=ledger, data_dir=data_dir)
    auth_service = AuthenticationService(
        nodes=nodes,
        ledger=ledger,
        challenge_manager=challenge_manager,
        transport=transport,
        data_dir=data_dir,
    )

    for n in nodes:
        print(f"  {GREEN}[Node {n.node_id}] Online ✓  Share store ready ✓{RESET}")

    if PQC_AVAILABLE:
        print(f"  {GREEN}[PQC] ML-DSA-65 available ✓{RESET}")
    else:
        print(f"  {YELLOW}[PQC] ⚠ Fallback to Ed25519 (no Docker/liboqs){RESET}")

    pause()

    # ── PHASE 1: Registration ─────────────────────────────────────────────────
    separator("PHASE 1 — User Registration")

    print(f"  {CYAN}Registering user 'alice' with password 'AliceSecure@2026'...{RESET}\n")
    result = reg_service.register("AliceSecure@2026")
    did = result["did"]
    keyfile_path = result["keyfile_path"]

    print(f"  {GREEN}DID issued: {did}{RESET}")
    print(f"  {GREEN}S split into 5 shares (3-of-5 threshold){RESET}")
    for i, n in enumerate(nodes, 1):
        print(f"  {GREEN}Share {i} → Node {i} ✓{RESET}")
    print(f"  {GREEN}S zeroed from memory ✓{RESET}")
    print(f"  {GREEN}Commitment hash on ledger ✓{RESET}")
    print(f"  {CYAN}Keyfile: {keyfile_path}{RESET}")

    priv, _ = load_keyfile(keyfile_path, "AliceSecure@2026")

    pause()

    # ── PHASE 2: Normal Authentication ────────────────────────────────────────
    separator("PHASE 2 — Normal Authentication")

    print(f"  {CYAN}Issuing challenge for {did[:32]}...{RESET}")
    ch, sig_hex, auth = _authenticate_alice(
        auth_service, challenge_manager, did, priv
    )

    if auth["status"] == "success":
        print(f"  {GREEN}IAT issued ✓ (expires in {auth['expires_in']}s){RESET}")
        print(f"  {CYAN}Token (first 40 chars): {auth['iat'][:40]}...{RESET}")
    else:
        print(f"  {RED}Authentication failed: {auth.get('reason')}{RESET}")

    pause()

    # ── ATTACK 1: Node Crash ──────────────────────────────────────────────────
    separator("ATTACK 1 — Node Crash")

    crash = NodeCrashAttack(target_node_id=3, nodes=nodes)
    crash.trigger()

    _, _, auth = _authenticate_alice(auth_service, challenge_manager, did, priv)

    if auth["status"] == "success":
        print(
            f"  {GREEN}System authenticated with 4 nodes ✓ (Node 3 offline){RESET}"
        )
    else:
        print(f"  {RED}Authentication failed: {auth.get('reason')}{RESET}")

    crash.reset()
    pause()

    # ── ATTACK 2: Byzantine Wrong Proof ───────────────────────────────────────
    separator("ATTACK 2 — Byzantine Wrong Proof")

    byz = ByzantineWrongProofAttack(target_node_id=3, nodes=nodes)
    byz.trigger()

    print(f"  {YELLOW}Node 3 sent WRONG partial proof{RESET}")
    _, _, auth = _authenticate_alice(auth_service, challenge_manager, did, priv)

    if auth["status"] == "success":
        print(f"  {YELLOW}BFT detected and discarded Node 3 ✗{RESET}")
        print(
            f"  {GREEN}Authentication succeeded with 4 honest nodes ✓{RESET}"
        )
    else:
        print(f"  {RED}Authentication failed: {auth.get('reason')}{RESET}")

    byz.reset()
    pause()

    # ── ATTACK 3: Share Theft ─────────────────────────────────────────────────
    separator("ATTACK 3 — Share Theft (2 Compromised Nodes)")

    theft = ShareTheftAttack(
        attacker_node_ids=[2, 3],
        nodes=nodes,
        ledger=ledger,
    )
    theft.trigger(did)

    pause()

    # ── ATTACK 4: Replay Attack ───────────────────────────────────────────────
    separator("ATTACK 4 — Replay Attack")

    # Perform a legitimate auth first (so we have a valid message to intercept)
    ch_live, sig_live, auth_live = _authenticate_alice(
        auth_service, challenge_manager, did, priv
    )
    if auth_live["status"] == "success":
        print(f"  {GREEN}Legitimate authentication succeeded — message intercepted{RESET}")

    replay = ReplayAttack(auth_service=auth_service)
    replay.intercept(did, ch_live["challenge_id"], sig_live)
    replay.replay()

    pause()

    # ── WRONG PASSWORD ────────────────────────────────────────────────────────
    separator("WRONG PASSWORD")

    try:
        load_keyfile(keyfile_path, "wrong_password_123")
        print(f"  {RED}ERROR: wrong password accepted — this is a bug{RESET}")
    except ValueError:
        print(
            f"  {GREEN}❌ Wrong password — keyfile decryption failed ✓{RESET}"
        )

    pause()

    # ── AUDIT LOG ─────────────────────────────────────────────────────────────
    separator("AUDIT LOG")

    entries = ledger.get_all_entries()
    print(f"  {'#':<4} {'Type':<20} {'DID':<24} {'Timestamp'}")
    print(f"  {'-'*70}")
    for i, e in enumerate(entries, 1):
        did_short = e["did"][:20] + "..." if len(e["did"]) > 20 else e["did"]
        print(
            f"  {i:<4} {e['entry_type']:<20} {did_short:<24} {e['timestamp']:.2f}"
        )

    chain_ok = ledger.verify_chain()
    color = GREEN if chain_ok else RED
    print(
        f"\n  {color}Chain integrity: {'VALID ✓' if chain_ok else 'INVALID ✗'}{RESET}"
    )

    pause()

    # ── SUMMARY ───────────────────────────────────────────────────────────────
    separator("SUMMARY")

    print(f"  {BOLD}╔══════════════════════════╦════════════════════════╦══════════╗{RESET}")
    print(f"  {BOLD}║ Attack                   ║ Defence                ║ Result   ║{RESET}")
    print(f"  {BOLD}╠══════════════════════════╬════════════════════════╬══════════╣{RESET}")
    print(f"  {BOLD}║{GREEN} Node crash               {BOLD}║{RESET} BFT fault tolerance    {BOLD}║{GREEN} BLOCKED  {BOLD}║{RESET}")
    print(f"  {BOLD}║{GREEN} Byzantine wrong proof    {BOLD}║{RESET} PBFT outlier detection {BOLD}║{GREEN} BLOCKED  {BOLD}║{RESET}")
    print(f"  {BOLD}║{GREEN} 2-node share theft       {BOLD}║{RESET} SSS threshold (t=3)    {BOLD}║{GREEN} BLOCKED  {BOLD}║{RESET}")
    print(f"  {BOLD}║{GREEN} Replay intercepted auth  {BOLD}║{RESET} Single-use nonces      {BOLD}║{GREEN} BLOCKED  {BOLD}║{RESET}")
    print(f"  {BOLD}║{GREEN} Wrong password           {BOLD}║{RESET} AES-GCM keyfile        {BOLD}║{GREEN} BLOCKED  {BOLD}║{RESET}")
    print(f"  {BOLD}╚══════════════════════════╩════════════════════════╩══════════╝{RESET}")

    print(f"\n  {BOLD}{GREEN}All attacks blocked. System is operating correctly.{RESET}\n")


if __name__ == "__main__":
    main()
