import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from authentication.authenticate import AuthenticationService
from authentication.challenge import ChallengeManager
import authentication.iat as _iat_module
from crypto import N_NODES
from crypto.pqc import PQC_AVAILABLE
from ledger.ledger import Ledger
from node.node import Node
from node.transport import get_transport
from registration.register import RegistrationService

# ── Module-level singletons (populated in lifespan) ───────────────────────────

_nodes: list[Node] = []
_ledger: Ledger | None = None
_challenge_manager: ChallengeManager | None = None
_reg_service: RegistrationService | None = None
_auth_service: AuthenticationService | None = None


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _nodes, _ledger, _challenge_manager, _reg_service, _auth_service

    data_dir = os.environ.get("DATA_DIR", "data")

    _nodes = [Node(node_id=i, data_dir=data_dir) for i in range(1, N_NODES + 1)]

    transport = get_transport()
    if hasattr(transport, "register_node"):          # LocalTransport
        for n in _nodes:
            transport.register_node(n.node_id, n)

    _ledger = Ledger(db_path=os.path.join(data_dir, "ledger.db"))
    _challenge_manager = ChallengeManager()

    _iat_module.init_system_keys(data_dir)

    _reg_service = RegistrationService(
        nodes=_nodes, ledger=_ledger, data_dir=data_dir
    )
    _auth_service = AuthenticationService(
        nodes=_nodes,
        ledger=_ledger,
        challenge_manager=_challenge_manager,
        transport=transport,
        data_dir=data_dir,
    )

    yield
    # No explicit cleanup needed for SQLite connections in this prototype.


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Decentralised IDP",
    version="1.0.0",
    description="Post-quantum decentralised identity provider using SSS + BFT",
    lifespan=lifespan,
)


# ── Pydantic models ───────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    password: str


class RegisterResponse(BaseModel):
    status: str
    did: str | None = None
    public_key: str | None = None
    keyfile_path: str | None = None
    message: str | None = None
    error: str | None = None


class ChallengeRequest(BaseModel):
    did: str


class ChallengeResponse(BaseModel):
    challenge_id: str
    nonce: str
    expires_in: int


class AuthRequest(BaseModel):
    did: str
    challenge_id: str
    signature: str    # hex-encoded ML-DSA-65 or Ed25519 signature


class AuthResponse(BaseModel):
    status: str
    iat: str | None = None
    expires_in: int | None = None
    reason: str | None = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.post("/register", response_model=RegisterResponse)
async def register(req: RegisterRequest):
    """Register a new user. Returns DID and keyfile path."""
    try:
        result = _reg_service.register(req.password)
        return RegisterResponse(
            status=result["status"],
            did=result["did"],
            public_key=result["public_key"],
            keyfile_path=result["keyfile_path"],
            message=result["message"],
        )
    except Exception as exc:
        return RegisterResponse(status="error", error=str(exc))


@app.post("/challenge", response_model=ChallengeResponse)
async def get_challenge(req: ChallengeRequest):
    """Issue a fresh challenge nonce for a DID."""
    result = _challenge_manager.issue(req.did)
    return ChallengeResponse(
        challenge_id=result["challenge_id"],
        nonce=result["nonce"],
        expires_in=result["expires_in"],
    )


@app.post("/authenticate", response_model=AuthResponse)
async def authenticate(req: AuthRequest):
    """Authenticate using a signed challenge. Returns IAT on success."""
    result = _auth_service.authenticate(req.did, req.challenge_id, req.signature)
    return AuthResponse(
        status=result["status"],
        iat=result.get("iat"),
        expires_in=result.get("expires_in"),
        reason=result.get("reason"),
    )


@app.get("/verify")
async def verify_token(token: str):
    """
    Verify an IAT token.
    Returns {"valid": bool, "did": str|None, "expires_at": int|None}
    """
    payload = _iat_module.verify_iat(token)
    if payload is None:
        return {"valid": False, "did": None, "expires_at": None}
    return {
        "valid": True,
        "did": payload.get("sub"),
        "expires_at": payload.get("exp"),
    }


@app.get("/health")
async def health():
    """
    Returns system health:
    {"status": "ok", "nodes": [{"id":1,"online":True}, ...],
     "pqc_available": bool, "ledger_chain_valid": bool}
    """
    return {
        "status": "ok",
        "nodes": [{"id": n.node_id, "online": n.online} for n in _nodes],
        "pqc_available": PQC_AVAILABLE,
        "ledger_chain_valid": _ledger.verify_chain(),
    }


# ── Internal endpoint (HTTP transport only, node-to-node) ─────────────────────

@app.post("/internal/partial_proof")
async def internal_partial_proof(body: dict):
    """
    Called by HTTPTransport.request_partial_proof().
    Body: {"did": str, "challenge_nonce": str (hex)}
    Returns 403 if NODE_TRANSPORT=local (not for external use).
    """
    transport_mode = os.environ.get("NODE_TRANSPORT", "local").lower()
    if transport_mode != "http":
        raise HTTPException(
            status_code=403,
            detail="Internal endpoint is only active in HTTP transport mode",
        )

    node_id = int(os.environ.get("NODE_ID", 1))
    node = next((n for n in _nodes if n.node_id == node_id), None)
    if node is None:
        raise HTTPException(status_code=404, detail=f"Node {node_id} not configured")

    try:
        proof = node.compute_partial_proof(
            body["did"],
            bytes.fromhex(body["challenge_nonce"]),
        )
        return proof
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
