"""
Lightweight node service — one process per container.
NODE_ID env var selects which node this is (1–5).
DATA_DIR env var points to the shared data volume.

Exposes:
  GET  /health
  POST /internal/partial_proof
"""
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from node.node import Node

_node: Node | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _node
    node_id = int(os.environ.get("NODE_ID", "1"))
    data_dir = os.environ.get("DATA_DIR", "data")
    _node = Node(node_id=node_id, data_dir=data_dir)
    print(f"[Node {node_id}] Ready — data_dir={data_dir}", flush=True)
    yield


app = FastAPI(title="IDP Node Service", lifespan=lifespan)


class PartialProofRequest(BaseModel):
    did: str
    challenge_nonce: str  # hex-encoded bytes


@app.get("/health")
async def health():
    return {"node_id": _node.node_id, "online": True}


@app.post("/internal/partial_proof")
async def partial_proof(req: PartialProofRequest):
    try:
        proof = _node.compute_partial_proof(
            req.did, bytes.fromhex(req.challenge_nonce)
        )
        return proof
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
