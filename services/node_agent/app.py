"""Standalone HTTPS node-agent service for the multi-container deployment."""

from __future__ import annotations

import base64
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from services.node_agent.agent import NodeAgent
from services.node_agent.internal_auth import verify_headers

node_id = int(os.getenv("RISKSHARE_NODE_ID", "0"))
if not 1 <= node_id <= 5:
    raise RuntimeError("RISKSHARE_NODE_ID must be between 1 and 5")
storage = Path(os.getenv("RISKSHARE_NODE_DATA", f"./data/node-{node_id}.sqlite3"))
secret = os.getenv("RISKSHARE_CONTROL_SECRET", "development-only-change-me").encode()
node = NodeAgent(node_id, storage, secret)


class ShareBody(BaseModel):
    vault_id: str
    epoch_id: str
    share: dict[str, object]


class ReleaseBody(BaseModel):
    token: str


class RetireBody(BaseModel):
    vault_id: str
    epoch_id: str


class SimulationBody(BaseModel):
    online: bool


def authorize(request: Request, body: bytes) -> None:
    timestamp = request.headers.get("X-RiskShare-Timestamp", "")
    nonce = request.headers.get("X-RiskShare-Nonce", "")
    signature = request.headers.get("X-RiskShare-Signature", "")
    if not verify_headers(
        secret, request.method, request.url.path, body, timestamp, nonce, signature
    ):
        raise HTTPException(status_code=401, detail="invalid internal request signature")
    if not node.consume_control_nonce(nonce):
        raise HTTPException(status_code=409, detail="replayed internal request")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    yield
    node.close()


app = FastAPI(title=f"RiskShare Node {node_id}", version="0.1.0", lifespan=lifespan)


@app.get("/health")
def health() -> dict[str, object]:
    return node.health()


@app.get("/internal/identity")
def identity() -> dict[str, object]:
    public = node.public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {"node_id": node_id, "ed25519_public_key": base64.b64encode(public).decode("ascii")}


@app.post("/internal/shares")
async def distribute(request: Request) -> dict[str, object]:
    body = await request.body()
    authorize(request, body)
    payload = ShareBody.model_validate_json(body)
    if payload.share.get("index") != node_id:
        raise HTTPException(status_code=422, detail="share index does not match node identity")
    if not node.distribute(payload.vault_id, payload.epoch_id, payload.share):
        raise HTTPException(status_code=503, detail="node unavailable")
    return {
        "node_id": node_id,
        "vault_id": payload.vault_id,
        "epoch_id": payload.epoch_id,
        "acknowledged": True,
    }


@app.post("/internal/release")
def release(body: ReleaseBody) -> dict[str, object]:
    result = node.release(body.token)
    if result is None:
        raise HTTPException(status_code=403, detail="share release denied")
    return result


@app.post("/internal/retire")
async def retire(request: Request) -> dict[str, object]:
    body = await request.body()
    authorize(request, body)
    payload = RetireBody.model_validate_json(body)
    node.retire_generation(payload.vault_id, payload.epoch_id)
    return {"node_id": node_id, "retired": True}


@app.post("/internal/trace-share")
async def trace_share(request: Request) -> dict[str, object]:
    if os.getenv("RISKSHARE_SIMULATION_ENABLED", "false").lower() != "true":
        raise HTTPException(status_code=404, detail="simulation endpoint disabled")
    body = await request.body()
    authorize(request, body)
    payload = RetireBody.model_validate_json(body)
    share = node.simulated_compromised_share(payload.vault_id, payload.epoch_id)
    if share is None:
        raise HTTPException(status_code=404, detail="share not found or node offline")
    return {"node_id": node_id, "share": share}


@app.post("/internal/simulation/online")
async def set_online(request: Request) -> dict[str, object]:
    if os.getenv("RISKSHARE_SIMULATION_ENABLED", "false").lower() != "true":
        raise HTTPException(status_code=404, detail="simulation endpoint disabled")
    body = await request.body()
    authorize(request, body)
    payload = SimulationBody.model_validate_json(body)
    node.set_online(payload.online)
    return {"node_id": node_id, "status": "online" if payload.online else "offline"}
