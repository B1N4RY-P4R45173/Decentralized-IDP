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

    Uses asyncio.wait_for inside each ThreadPoolExecutor thread so that
    Docker's internal network SYN-drop behaviour (which ignores socket-level
    timeouts) is properly cancelled after NODE_TIMEOUT seconds.
    """

    NODE_TIMEOUT = 2.0   # seconds per node request

    def __init__(self):
        peers_env = os.environ.get("NODE_PEERS", "")
        self._peers: dict[int, str] = {}
        if peers_env:
            for i, addr in enumerate(peers_env.split(","), start=1):
                self._peers[i] = addr.strip()

    def request_partial_proof(
        self,
        target_node_id: int,
        did: str,
        challenge_nonce_hex: str,
    ) -> dict | None:
        import asyncio
        import httpx

        addr = self._peers.get(target_node_id)
        if not addr:
            return None

        async def _fetch() -> dict | None:
            async with httpx.AsyncClient() as client:
                resp = await asyncio.wait_for(
                    client.post(
                        f"http://{addr}/internal/partial_proof",
                        json={"did": did, "challenge_nonce": challenge_nonce_hex},
                    ),
                    timeout=self.NODE_TIMEOUT,
                )
                return resp.json() if resp.status_code == 200 else None

        try:
            # This runs in a ThreadPoolExecutor thread (outside FastAPI's event
            # loop), so asyncio.run() creates a fresh loop — safe to call here.
            return asyncio.run(_fetch())
        except Exception as e:
            print(f"[Transport] HTTP error node {target_node_id}: {e}")
            return None

    async def request_partial_proof_async(
        self,
        target_node_id: int,
        did: str,
        challenge_nonce_hex: str,
    ) -> dict | None:
        """
        Async variant — call from FastAPI's event loop via asyncio.gather.
        asyncio.wait_for properly cancels after NODE_TIMEOUT when called
        from the main event loop (unlike ThreadPoolExecutor threads).
        """
        import asyncio
        import httpx

        addr = self._peers.get(target_node_id)
        if not addr:
            return None
        try:
            async with httpx.AsyncClient() as client:
                resp = await asyncio.wait_for(
                    client.post(
                        f"http://{addr}/internal/partial_proof",
                        json={"did": did, "challenge_nonce": challenge_nonce_hex},
                    ),
                    timeout=self.NODE_TIMEOUT,
                )
                return resp.json() if resp.status_code == 200 else None
        except Exception as e:
            print(f"[Transport] async error node {target_node_id}: {e}")
            return None


def get_transport() -> NodeTransport:
    """Factory: returns LocalTransport or HTTPTransport from NODE_TRANSPORT env."""
    mode = os.environ.get("NODE_TRANSPORT", "local").lower()
    if mode == "http":
        return HTTPTransport()
    return LocalTransport()
