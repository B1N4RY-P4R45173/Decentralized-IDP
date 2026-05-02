"""
Append-only audit ledger with SHA-3 hash chain.
Simulates a distributed ledger using SQLite.
Every entry is cryptographically linked to the previous one.
Tampering with any entry invalidates all subsequent hashes.
"""

import hashlib
import json
import os
import sqlite3
import time
from typing import Any

ENTRY_TYPES = {
    "DID_REGISTER",
    "AUTH_SUCCESS",
    "AUTH_FAIL",
    "SHARE_REVOKE",
}


class Ledger:

    def __init__(self, db_path: str = "data/ledger.db"):
        parent = os.path.dirname(db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS entries (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_type     TEXT    NOT NULL,
                did            TEXT    NOT NULL,
                data_json      TEXT    NOT NULL,
                timestamp      REAL    NOT NULL,
                entry_hash     TEXT    NOT NULL,
                previous_hash  TEXT    NOT NULL
            )
        """)
        self.conn.commit()

    def _last_hash(self) -> str:
        row = self.conn.execute(
            "SELECT entry_hash FROM entries ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else "0" * 64

    @staticmethod
    def _compute_hash(
        previous_hash: str,
        entry_type: str,
        did: str,
        data_json: str,
        timestamp: float,
    ) -> str:
        h = hashlib.sha3_256()
        h.update(previous_hash.encode())
        h.update(entry_type.encode())
        h.update(did.encode())
        h.update(data_json.encode())
        # Encode timestamp as its repr so the value is identical on readback
        h.update(repr(timestamp).encode())
        return h.hexdigest()

    def append(self, entry_type: str, did: str, data: dict[str, Any]) -> str:
        data_json = json.dumps(data, sort_keys=True)
        timestamp = time.time()
        previous_hash = self._last_hash()
        entry_hash = self._compute_hash(
            previous_hash, entry_type, did, data_json, timestamp
        )
        self.conn.execute(
            """
            INSERT INTO entries
                (entry_type, did, data_json, timestamp, entry_hash, previous_hash)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (entry_type, did, data_json, timestamp, entry_hash, previous_hash),
        )
        self.conn.commit()
        return entry_hash

    def verify_chain(self) -> bool:
        rows = self.conn.execute(
            "SELECT id, entry_type, did, data_json, timestamp, entry_hash, previous_hash "
            "FROM entries ORDER BY id ASC"
        ).fetchall()

        expected_previous = "0" * 64
        for row in rows:
            _, entry_type, did, data_json, timestamp, stored_hash, stored_prev = row

            if stored_prev != expected_previous:
                return False

            recomputed = self._compute_hash(
                stored_prev, entry_type, did, data_json, timestamp
            )
            if recomputed != stored_hash:
                return False

            expected_previous = stored_hash

        return True

    # ── DID_REGISTER lookup helpers ───────────────────────────────────────────

    def _get_register_data(self, did: str) -> dict | None:
        row = self.conn.execute(
            "SELECT data_json FROM entries "
            "WHERE entry_type = 'DID_REGISTER' AND did = ? "
            "ORDER BY id DESC LIMIT 1",
            (did,),
        ).fetchone()
        if row is None:
            return None
        return json.loads(row[0])

    def get_did_document(self, did: str) -> dict | None:
        return self._get_register_data(did)

    def get_commitment_hash(self, did: str) -> str | None:
        data = self._get_register_data(did)
        return data["commitment_hash"] if data else None

    def get_registration_nonce(self, did: str) -> bytes | None:
        data = self._get_register_data(did)
        return bytes.fromhex(data["nonce"]) if data else None

    def get_feldman_commitments(self, did: str) -> list[bytes] | None:
        data = self._get_register_data(did)
        if data is None:
            return None
        return [bytes.fromhex(c) for c in data["feldman_commitments"]]

    def get_public_key(self, did: str) -> bytes | None:
        data = self._get_register_data(did)
        return bytes.fromhex(data["public_key"]) if data else None

    def get_all_entries(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, entry_type, did, data_json, timestamp, entry_hash "
            "FROM entries ORDER BY id ASC"
        ).fetchall()
        return [
            {
                "id": r[0],
                "entry_type": r[1],
                "did": r[2],
                "data": json.loads(r[3]),
                "timestamp": r[4],
                "entry_hash": r[5],
            }
            for r in rows
        ]
