import secrets
import time
import uuid

from crypto import CHALLENGE_TTL_SECONDS


class ChallengeManager:
    """
    Issues and tracks single-use challenge nonces.
    Challenges expire after CHALLENGE_TTL_SECONDS (30 s).
    A challenge can only be used ONCE — deleted on first use.
    This prevents replay attacks.
    """

    def __init__(self):
        # challenge_id (str) → {'nonce': bytes, 'did': str, 'expires_at': float}
        self._pending: dict[str, dict] = {}

    def issue(self, did: str) -> dict:
        nonce = secrets.token_bytes(32)
        challenge_id = str(uuid.uuid4())
        self._pending[challenge_id] = {
            "nonce": nonce,
            "did": did,
            "expires_at": time.time() + CHALLENGE_TTL_SECONDS,
        }
        return {
            "challenge_id": challenge_id,
            "nonce": nonce.hex(),
            "expires_in": CHALLENGE_TTL_SECONDS,
        }

    def peek(self, challenge_id: str) -> bytes | None:
        """Return nonce without consuming — used for async pre-collection."""
        entry = self._pending.get(challenge_id)
        if entry is None or time.time() > entry["expires_at"]:
            return None
        return entry["nonce"]

    def consume(self, challenge_id: str) -> bytes | None:
        entry = self._pending.get(challenge_id)
        if entry is None:
            return None
        if time.time() > entry["expires_at"]:
            del self._pending[challenge_id]
            return None
        del self._pending[challenge_id]   # single use
        return entry["nonce"]

    def _cleanup_expired(self) -> None:
        now = time.time()
        expired = [cid for cid, v in self._pending.items() if v["expires_at"] < now]
        for cid in expired:
            del self._pending[cid]
