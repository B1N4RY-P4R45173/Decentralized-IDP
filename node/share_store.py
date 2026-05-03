import hashlib
import os
import secrets
import sqlite3

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class ShareStore:
    """
    Encrypted per-node SQLite store mapping DID → SSS share.
    Each node's y-coordinate is AES-256-GCM encrypted at rest.
    The node's AES key is generated once and persisted to store.key.
    """

    def __init__(self, node_id: int, data_dir: str = "data"):
        node_dir = os.path.join(data_dir, f"node_{node_id}")
        os.makedirs(node_dir, exist_ok=True)

        key_path = os.path.join(node_dir, "store.key")
        if os.path.exists(key_path):
            with open(key_path, "rb") as f:
                self._aes_key = f.read()
        else:
            self._aes_key = secrets.token_bytes(32)
            with open(key_path, "wb") as f:
                f.write(self._aes_key)

        db_path = os.path.join(node_dir, "shares.db")
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS shares (
                did                TEXT PRIMARY KEY,
                x_coord            INTEGER NOT NULL,
                y_coord_encrypted  BLOB NOT NULL,
                aes_nonce          BLOB NOT NULL,
                share_hash         TEXT NOT NULL,
                feldman_commitment BLOB,
                registered_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        self.conn.commit()

    def store_share(
        self,
        did: str,
        x: int,
        y: int,
        feldman_commitment: bytes | None = None,
    ) -> None:
        nonce = secrets.token_bytes(12)
        aes = AESGCM(self._aes_key)
        y_encrypted = aes.encrypt(nonce, y.to_bytes(32, "big"), did.encode())
        share_hash = hashlib.sha3_256((str(x) + str(y)).encode()).hexdigest()

        self.conn.execute(
            """
            INSERT OR REPLACE INTO shares
                (did, x_coord, y_coord_encrypted, aes_nonce, share_hash, feldman_commitment)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (did, x, y_encrypted, nonce, share_hash, feldman_commitment),
        )
        self.conn.commit()

    def get_share(self, did: str) -> tuple[int, int] | None:
        row = self.conn.execute(
            "SELECT x_coord, y_coord_encrypted, aes_nonce, share_hash FROM shares WHERE did = ?",
            (did,),
        ).fetchone()
        if row is None:
            return None

        x, y_encrypted, nonce, stored_hash = row
        aes = AESGCM(self._aes_key)
        y_bytes = aes.decrypt(bytes(nonce), bytes(y_encrypted), did.encode())
        y = int.from_bytes(y_bytes, "big")

        computed_hash = hashlib.sha3_256((str(x) + str(y)).encode()).hexdigest()
        if computed_hash != stored_hash:
            raise ValueError(f"Share integrity check failed for DID {did!r} — data may be tampered")

        return x, y

    def delete_share(self, did: str) -> None:
        self.conn.execute("DELETE FROM shares WHERE did = ?", (did,))
        self.conn.commit()

    def has_share(self, did: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM shares WHERE did = ?", (did,)
        ).fetchone()
        return row is not None
