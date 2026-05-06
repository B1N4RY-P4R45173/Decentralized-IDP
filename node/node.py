import os
import secrets as _secrets

from crypto import P
from crypto.pqc import kem_generate_keypair
from node.share_store import ShareStore
from node.partial_proof import compute_partial_proof as _compute_proof


class NodeOfflineError(Exception):
    pass


class ShareNotFoundError(Exception):
    pass


class Node:
    """
    A single BFT identity node. Holds one SSS share per registered DID.
    Exposes one public method: compute_partial_proof().
    """

    def __init__(self, node_id: int, data_dir: str = "data"):
        self.node_id = node_id
        self.online = True       # set False to simulate crash
        self.byzantine = False   # set True to simulate Byzantine
        self.share_store = ShareStore(node_id, data_dir)
        # ShareStore already created node_dir; now generate/load KEM keys
        self._init_kem_keys(data_dir)

    def _init_kem_keys(self, data_dir: str) -> None:
        node_dir = os.path.join(data_dir, f"node_{self.node_id}")
        priv_path = os.path.join(node_dir, "kem.key")
        pub_path = os.path.join(node_dir, "kem.pub")
        if os.path.exists(priv_path) and os.path.exists(pub_path):
            with open(priv_path, "rb") as f:
                self._kem_private_key = f.read()
            with open(pub_path, "rb") as f:
                self._kem_public_key = f.read()
        else:
            priv, pub = kem_generate_keypair()
            with open(priv_path, "wb") as f:
                f.write(priv)
            with open(pub_path, "wb") as f:
                f.write(pub)
            self._kem_private_key = priv
            self._kem_public_key = pub

    @property
    def kem_public_key(self) -> bytes:
        return self._kem_public_key

    def compute_partial_proof(self, did: str, challenge_nonce: bytes) -> dict:
        if not self.online:
            raise NodeOfflineError(f"Node {self.node_id} is offline")

        share = self.share_store.get_share(did)
        if share is None:
            raise ShareNotFoundError(f"Node {self.node_id} has no share for {did!r}")

        if self.byzantine:
            import hashlib
            challenge_hash = hashlib.sha3_256(challenge_nonce).hexdigest()
            H = int(challenge_hash, 16) % P
            fake_value = _secrets.randbelow(P - 1) + 1
            return {
                "node_id": self.node_id,
                "x": share[0],
                "partial_value": fake_value,
                "H": H,
                "challenge_hash": challenge_hash,
            }

        return _compute_proof(share, challenge_nonce, self.node_id)
