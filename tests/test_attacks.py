"""Tests for all four attack scenarios."""

import pytest

from crypto.keyfile import load_keyfile
from crypto.pqc import sign as pqc_sign
from simulate.attacks import (
    ByzantineWrongProofAttack,
    NodeCrashAttack,
    ReplayAttack,
    ShareTheftAttack,
)

_PASSWORD = "AttackTest@2026"


def _register_and_load_key(reg_service, password=_PASSWORD):
    result = reg_service.register(password)
    priv, _ = load_keyfile(result["keyfile_path"], password)
    return result, priv


def _sign(priv: bytes, nonce_hex: str, did: str) -> str:
    sig = pqc_sign(priv, bytes.fromhex(nonce_hex) + did.encode("utf-8"))
    return sig.hex()


def _do_auth(auth_service, challenge_manager, did, priv):
    ch = challenge_manager.issue(did)
    sig_hex = _sign(priv, ch["nonce"], did)
    return ch, sig_hex, auth_service.authenticate(did, ch["challenge_id"], sig_hex)


# ── required tests ─────────────────────────────────────────────────────────────

def test_crash_attack(
    nodes, registration_service, authentication_service, challenge_manager
):
    result, priv = _register_and_load_key(registration_service)
    did = result["did"]

    attack = NodeCrashAttack(target_node_id=3, nodes=nodes)
    attack.trigger()

    try:
        _, _, auth = _do_auth(authentication_service, challenge_manager, did, priv)
        assert auth["status"] == "success", f"Expected success, got: {auth}"
    finally:
        attack.reset()


def test_byzantine_attack(
    nodes, registration_service, authentication_service, challenge_manager
):
    result, priv = _register_and_load_key(registration_service)
    did = result["did"]

    attack = ByzantineWrongProofAttack(target_node_id=3, nodes=nodes)
    attack.trigger()

    try:
        _, _, auth = _do_auth(authentication_service, challenge_manager, did, priv)
        assert auth["status"] == "success", f"Expected success, got: {auth}"
    finally:
        attack.reset()


def test_share_theft(nodes, registration_service, ledger):
    result, _ = _register_and_load_key(registration_service)
    did = result["did"]

    attack = ShareTheftAttack(
        attacker_node_ids=[2, 3],
        nodes=nodes,
        ledger=ledger,
    )
    succeeded = attack.trigger(did)
    assert succeeded is False, "2 shares must NOT be enough to reconstruct S"


def test_replay_attack(
    registration_service, authentication_service, challenge_manager
):
    result, priv = _register_and_load_key(registration_service)
    did = result["did"]

    # Perform a legitimate auth
    ch, sig_hex, auth = _do_auth(
        authentication_service, challenge_manager, did, priv
    )
    assert auth["status"] == "success"

    # Try to replay the same message
    replay = ReplayAttack(auth_service=authentication_service)
    replay.intercept(did, ch["challenge_id"], sig_hex)
    replay_result = replay.replay()

    assert replay_result["status"] == "failed"
    assert replay_result["reason"] == "challenge_expired_or_invalid"
