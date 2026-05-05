"""
Transport abstraction — swap between local (in-process) and HTTP
without changing any other code.

    NODE_TRANSPORT=local  → LocalTransport (default, no network needed)
    NODE_TRANSPORT=http   → HTTPTransport  (real network, Docker/5 machines)
"""

import os
from abc import ABC, abstractmethod


class NodeTransport(ABC):

    @abstractmethod
    def request_partial_proof(
        self,
        target_node_id: int,
        did: str,
        challenge_nonce_hex: str,
    ) -> dict | None:
        """
        Ask target node to compute and return its partial proof.
        Returns proof dict on success, None if node is offline/failed.
        """


class LocalTransport(NodeTransport):
    """
    In-process transport — nodes are Python objects in the same process.
    Used for unit tests and single-machine demo. No network required.
    """

    def __init__(self):
        self._nodes: dict[int, object] = {}

    def register_node(self, node_id: int, node: object) -> None:
        self._nodes[node_id] = node

    def request_partial_proof(
        self,
        target_node_id: int,
        did: str,
        challenge_nonce_hex: str,
    ) -> dict | None:
        node = self._nodes.get(target_node_id)
        if node is None or not node.online:
            return None
        try:
            return node.compute_partial_proof(did, bytes.fromhex(challenge_nonce_hex))
        except Exception as e:
            print(f"[Transport] Node {target_node_id} error: {e}")
            return None


class HTTPTransport(NodeTransport):
    """
    Real HTTP transport — each node is a separate process/container.
    Reads peer addresses from NODE_PEERS env var:
        NODE_PEERS=node1:8001,node2:8002,...
    """

    def __init__(self):
        import httpx

        peers_env = os.environ.get("NODE_PEERS", "")
        self._peers: dict[int, str] = {}
        if peers_env:
            for i, addr in enumerate(peers_env.split(","), start=1):
                self._peers[i] = addr.strip()
        self._client = httpx.Client(timeout=5.0)

    def request_partial_proof(
        self,
        target_node_id: int,
        did: str,
        challenge_nonce_hex: str,
    ) -> dict | None:
        addr = self._peers.get(target_node_id)
        if not addr:
            return None
        try:
            url = f"http://{addr}/internal/partial_proof"
            resp = self._client.post(
                url,
                json={"did": did, "challenge_nonce": challenge_nonce_hex},
            )
            if resp.status_code == 200:
                return resp.json()
            return None
        except Exception as e:
            print(f"[Transport] HTTP error node {target_node_id}: {e}")
            return None


def get_transport() -> NodeTransport:
    """Factory: returns LocalTransport or HTTPTransport from NODE_TRANSPORT env."""
    mode = os.environ.get("NODE_TRANSPORT", "local").lower()
    if mode == "http":
        return HTTPTransport()
    return LocalTransport()
