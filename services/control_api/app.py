"""FastAPI demonstrator control plane with authenticated vault operations."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from collections import defaultdict, deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives import serialization
from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from core.crypto.abss.abss_i import ShareholderShare
from core.crypto.ttss.ttss_i import EmbeddedShareBox
from core.crypto.ttss.ttss_ii import trace_ii, verify_ii
from core.quorum_manager.policy import Profile
from core.risk_engine.engine import EventKind, RiskEvent
from services.control_api.db import (
    AuditRow,
    EpochRow,
    RecoveryRow,
    SessionLocal,
    TraceCaseRow,
    VaultRow,
)
from services.control_api.runtime import runtime


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


class LoginBody(BaseModel):
    username: str
    password: str


class VaultBody(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class InitializeBody(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    content_base64: str


class RotateBody(BaseModel):
    threshold: int | None = Field(default=None, ge=2, le=4)
    risk_score: int | None = Field(default=None, ge=0, le=100)
    finish_policy_transition: bool = True


class RecoveryBody(BaseModel):
    vault_id: str


class AttackBody(BaseModel):
    kind: EventKind
    node_id: int = Field(ge=1, le=5)
    critical: bool = False
    take_node_offline: bool = False


class TraceBody(BaseModel):
    vault_id: str
    epoch_id: str | None = None
    leaked_node_ids: list[int] = Field(min_length=1, max_length=4)


class ConnectionHub:
    def __init__(self) -> None:
        self.connections: set[asyncio.Queue[dict[str, object]]] = set()

    async def publish(self, event: dict[str, object]) -> None:
        if _redis_events is not None:
            await _redis_events.xadd(
                "riskshare:events",
                {"json": json.dumps(event, sort_keys=True, separators=(",", ":"))},
                maxlen=10_000,
                approximate=True,
            )
        for queue in tuple(self.connections):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                self.connections.discard(queue)


hub = ConnectionHub()
_redis_events: Redis | None = None
bearer = HTTPBearer(auto_error=False)
AUTH_SECRET = os.getenv("RISKSHARE_AUTH_SECRET", "development-auth-secret-change-me").encode()
_revoked_tokens: set[str] = set()
_rate_buckets: dict[tuple[str, str], deque[float]] = defaultdict(deque)


def _issue_auth_token(username: str, role: str) -> str:
    body = _json(
        {
            "sub": username,
            "role": role,
            "exp": int(time.time()) + 3600,
            "jti": secrets.token_urlsafe(16),
        }
    )
    signature = hmac.new(AUTH_SECRET, body, hashlib.sha256).digest()
    encoded_body = base64.urlsafe_b64encode(body).decode().rstrip("=")
    encoded_signature = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return f"{encoded_body}.{encoded_signature}"


def _read_auth_token(token: str) -> dict[str, str]:
    try:
        if hashlib.sha256(token.encode()).hexdigest() in _revoked_tokens:
            raise ValueError("revoked")
        encoded, signature = token.split(".", 1)
        body = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        supplied = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        if not hmac.compare_digest(hmac.new(AUTH_SECRET, body, hashlib.sha256).digest(), supplied):
            raise ValueError("bad signature")
        claims = json.loads(body)
        if int(claims["exp"]) < int(time.time()):
            raise ValueError("expired")
        return {"username": str(claims["sub"]), "role": str(claims["role"])}
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=401, detail="invalid or expired bearer token") from exc


def current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> dict[str, str]:
    if credentials is None:
        raise HTTPException(status_code=401, detail="bearer token required")
    return _read_auth_token(credentials.credentials)


def require_admin(user: dict[str, str] = Depends(current_user)) -> dict[str, str]:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="administrator role required")
    return user


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        host = request.client.host if request.client else "unknown"
        path = request.url.path
        limit = 8 if path == "/auth/login" else 120
        key = (host, path if path == "/auth/login" else "api")
        now = time.monotonic()
        bucket = _rate_buckets[key]
        while bucket and bucket[0] <= now - 60:
            bucket.popleft()
        if len(bucket) >= limit:
            return JSONResponse({"detail": "rate limit exceeded; retry later"}, status_code=429)
        bucket.append(now)
        return await call_next(request)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    global _redis_events
    config = Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))
    command.upgrade(config, "head")
    with SessionLocal() as session:
        runtime.load_risk_history(session)
        runtime.restore_policy(session)
    redis_url = os.getenv("RISKSHARE_REDIS_URL")
    if redis_url:
        _redis_events = Redis.from_url(redis_url, decode_responses=True)
        await _redis_events.ping()
    yield
    if _redis_events is not None:
        await _redis_events.aclose()
        _redis_events = None
    for node in runtime.nodes:
        node.close()


app = FastAPI(title="RiskShare Control API", version="0.1.0", lifespan=lifespan)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("RISKSHARE_CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
static_dir = Path(__file__).resolve().parents[2] / "apps" / "dashboard" / "out"
if static_dir.exists():
    app.mount("/control-room", StaticFiles(directory=static_dir, html=True), name="control-room")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "local-research-demonstrator"}


@app.post("/auth/login")
def login(body: LoginBody) -> dict[str, str]:
    users = {
        "admin": (os.getenv("RISKSHARE_ADMIN_PASSWORD", "dev-admin-change-me"), "admin"),
        "operator": (
            os.getenv("RISKSHARE_OPERATOR_PASSWORD", "dev-operator-change-me"),
            "operator",
        ),
    }
    stored = users.get(body.username)
    if stored is None or not hmac.compare_digest(stored[0], body.password):
        raise HTTPException(status_code=401, detail="invalid username or password")
    return {
        "access_token": _issue_auth_token(body.username, stored[1]),
        "token_type": "bearer",
        "role": stored[1],
    }


@app.get("/auth/me")
def me(user: dict[str, str] = Depends(current_user)) -> dict[str, str]:
    return user


@app.post("/auth/logout")
def logout(
    user: dict[str, str] = Depends(current_user),
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> dict[str, str]:
    if credentials is not None:
        _revoked_tokens.add(hashlib.sha256(credentials.credentials.encode()).hexdigest())
    return {"status": "logged_out", "user": user["username"]}


@app.post("/vaults")
def create_vault(
    body: VaultBody, user: dict[str, str] = Depends(current_user)
) -> dict[str, object]:
    row = VaultRow(id=str(uuid.uuid4()), name=body.name)
    with SessionLocal.begin() as session:
        session.add(row)
        runtime.audit(
            session, "vault.created", user["username"], {"vault_id": row.id, "name": row.name}
        )
    return {"id": row.id, "name": row.name, "status": "created"}


@app.post("/vaults/{vault_id}/initialize")
async def initialize_vault(
    vault_id: str, body: InitializeBody, user: dict[str, str] = Depends(require_admin)
) -> dict[str, object]:
    try:
        content = base64.b64decode(body.content_base64, validate=True)
    except Exception as exc:
        raise HTTPException(status_code=422, detail="content_base64 is malformed") from exc
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="demonstrator upload limit is 10 MiB")
    with SessionLocal.begin() as session:
        vault = session.get(VaultRow, vault_id)
        if vault is None:
            raise HTTPException(status_code=404, detail="vault not found")
        if vault.active_epoch_id:
            raise HTTPException(status_code=409, detail="vault is already initialized")
        try:
            epoch = runtime.create_epoch(
                session,
                vault,
                content,
                Path(body.filename).name,
                runtime.quorum.state.active_threshold,
            )
        except Exception as exc:
            runtime.audit(
                session,
                "epoch.transition.failed",
                user["username"],
                {"vault_id": vault_id, "reason": str(exc)[:160]},
            )
            session.commit()
            raise HTTPException(
                status_code=503, detail="initial share distribution failed; vault was not activated"
            ) from exc
        vault.active_epoch_id = epoch.id
        runtime.audit(
            session,
            "epoch.transition.completed",
            user["username"],
            {"vault_id": vault_id, "epoch_id": epoch.id, "threshold": epoch.threshold},
        )
        response = _epoch_view(epoch)
    await hub.publish(
        {"type": "epoch.transition.completed", "vault_id": vault_id, "epoch_id": response["id"]}
    )
    return response


def _epoch_view(epoch: EpochRow) -> dict[str, object]:
    return {
        "id": epoch.id,
        "status": epoch.status,
        "threshold": epoch.threshold,
        "n": epoch.n,
        "encryption_version": epoch.encryption_version,
        "created_at": epoch.created_at.isoformat() if epoch.created_at else None,
    }


def _vault_view(session: Session, vault: VaultRow) -> dict[str, object]:
    epoch = session.get(EpochRow, vault.active_epoch_id) if vault.active_epoch_id else None
    return {
        "id": vault.id,
        "name": vault.name,
        "status": "active" if epoch else "uninitialized",
        "active_epoch": _epoch_view(epoch) if epoch else None,
    }


@app.get("/vaults")
def list_vaults(user: dict[str, str] = Depends(current_user)) -> list[dict[str, object]]:
    with SessionLocal() as session:
        return [
            _vault_view(session, row)
            for row in session.scalars(select(VaultRow).order_by(VaultRow.created_at.desc())).all()
        ]


@app.get("/vaults/{vault_id}")
def get_vault(vault_id: str, user: dict[str, str] = Depends(current_user)) -> dict[str, object]:
    with SessionLocal() as session:
        vault = session.get(VaultRow, vault_id)
        if vault is None:
            raise HTTPException(status_code=404, detail="vault not found")
        return _vault_view(session, vault)


@app.get("/vaults/{vault_id}/epochs")
def list_epochs(
    vault_id: str, user: dict[str, str] = Depends(current_user)
) -> list[dict[str, object]]:
    with SessionLocal() as session:
        vault = session.get(VaultRow, vault_id)
        if vault is None:
            raise HTTPException(status_code=404, detail="vault not found")
        rows = session.scalars(
            select(EpochRow)
            .where(EpochRow.vault_id == vault_id)
            .order_by(EpochRow.created_at.desc())
        ).all()
        return [_epoch_view(row) for row in rows]


@app.post("/vaults/{vault_id}/rotate")
async def rotate_vault(
    vault_id: str, body: RotateBody, user: dict[str, str] = Depends(require_admin)
) -> dict[str, object]:
    retired_epoch_id: str | None = None
    with SessionLocal.begin() as session:
        vault = session.get(VaultRow, vault_id)
        if vault is None or not vault.active_epoch_id:
            raise HTTPException(status_code=404, detail="active vault not found")
        old_epoch = session.get(EpochRow, vault.active_epoch_id)
        assert old_epoch is not None
        transition_profile: Profile | None = None
        if body.risk_score is not None:
            transition_profile = runtime.quorum.request_transition(
                body.risk_score,
                now=datetime.now(UTC),
                administrator_authorized=True,
            )
        threshold = body.threshold or (
            transition_profile.threshold
            if transition_profile
            else runtime.quorum.state.transition_target.threshold
            if runtime.quorum.state.transition_target
            else runtime.quorum.state.active_threshold
        )
        if (
            threshold != old_epoch.threshold
            and threshold != runtime.quorum.state.active_threshold
            and transition_profile is None
            and runtime.quorum.state.transition_target is None
        ):
            raise HTTPException(
                status_code=409, detail="threshold change requires a policy transition"
            )
        if (
            runtime.quorum.state.recovery_frozen
            and runtime.quorum.state.transition_target is None
            and threshold != runtime.quorum.state.active_threshold
        ):
            raise HTTPException(
                status_code=423, detail="recovery is frozen after a failed transition"
            )
        try:
            old_dek = runtime.recover_dek(vault.id, old_epoch, str(uuid.uuid4()))
            plaintext = runtime._decrypt_epoch(old_epoch, old_dek)
            new_epoch = runtime.create_epoch(
                session, vault, plaintext, old_epoch.filename, threshold
            )
            old_epoch.status = "RETIRED"
            retired_epoch_id = old_epoch.id
            vault.active_epoch_id = new_epoch.id
            if runtime.quorum.state.transition_target and body.finish_policy_transition:
                runtime.quorum.complete_transition(new_epoch=new_epoch.id, success=True)
            runtime.audit(
                session,
                "epoch.transition.completed",
                user["username"],
                {
                    "vault_id": vault.id,
                    "old_epoch": old_epoch.id,
                    "epoch_id": new_epoch.id,
                    "threshold": threshold,
                },
            )
        except Exception as exc:
            if runtime.quorum.state.transition_target and body.finish_policy_transition:
                runtime.quorum.complete_transition(new_epoch="failed", success=False)
            runtime.audit(
                session,
                "epoch.transition.failed",
                user["username"],
                {"vault_id": vault.id, "reason": str(exc)[:160]},
            )
            session.commit()
            raise HTTPException(
                status_code=503, detail="epoch rotation failed; recovery is frozen"
            ) from exc
        response = _epoch_view(new_epoch)
    if retired_epoch_id:
        for node in runtime.nodes:
            node.retire_generation(vault_id, retired_epoch_id)
        runtime.trace_keys.pop(retired_epoch_id, None)
        runtime.trace_contexts.pop(retired_epoch_id, None)
        if runtime.quorum.state.recovery_frozen and runtime.quorum.state.transition_target is None:
            with SessionLocal() as session:
                active_thresholds = {
                    row.threshold
                    for row in session.scalars(
                        select(EpochRow).where(EpochRow.status == "ACTIVE")
                    ).all()
                }
                if active_thresholds == {runtime.quorum.state.active_threshold}:
                    runtime.quorum.confirm_all_vaults_at_active_threshold()
    await hub.publish(
        {"type": "epoch.transition.completed", "vault_id": vault_id, "epoch_id": response["id"]}
    )
    return response


@app.post("/recovery-requests")
def request_recovery(
    body: RecoveryBody, user: dict[str, str] = Depends(current_user)
) -> dict[str, object]:
    if not runtime.quorum.recovery_allowed:
        raise HTTPException(
            status_code=423, detail="recovery is frozen during an unsafe epoch transition"
        )
    with SessionLocal.begin() as session:
        vault = session.get(VaultRow, body.vault_id)
        if vault is None or not vault.active_epoch_id:
            raise HTTPException(status_code=404, detail="active vault not found")
        epoch = session.get(EpochRow, vault.active_epoch_id)
        assert epoch is not None
        row = RecoveryRow(
            id=str(uuid.uuid4()),
            vault_id=vault.id,
            epoch_id=epoch.id,
            requested_by=user["username"],
            status="PENDING",
            required_shares=epoch.threshold,
        )
        session.add(row)
        runtime.audit(
            session,
            "recovery.started",
            user["username"],
            {"request_id": row.id, "vault_id": vault.id, "epoch_id": epoch.id},
        )
        return {
            "id": row.id,
            "status": row.status,
            "required_shares": row.required_shares,
            "epoch_id": row.epoch_id,
        }


@app.get("/recovery-requests/{request_id}")
def get_recovery(
    request_id: str, user: dict[str, str] = Depends(current_user)
) -> dict[str, object]:
    with SessionLocal() as session:
        row = session.get(RecoveryRow, request_id)
        if row is None:
            raise HTTPException(status_code=404, detail="recovery request not found")
        return {
            "id": row.id,
            "vault_id": row.vault_id,
            "epoch_id": row.epoch_id,
            "requested_by": row.requested_by,
            "status": row.status,
            "required_shares": row.required_shares,
            "received_shares": row.received_shares,
        }


@app.post("/recovery-requests/{request_id}/approve")
def approve_recovery(
    request_id: str, user: dict[str, str] = Depends(require_admin)
) -> dict[str, object]:
    with SessionLocal.begin() as session:
        recovery = session.get(RecoveryRow, request_id)
        if recovery is None:
            raise HTTPException(status_code=404, detail="recovery request not found")
        if recovery.requested_by == user["username"]:
            raise HTTPException(
                status_code=403, detail="requester cannot approve their own recovery"
            )
        if recovery.status != "PENDING":
            raise HTTPException(status_code=409, detail="recovery request is not pending")
        if not runtime.quorum.recovery_allowed:
            recovery.status = "DENIED"
            runtime.audit(
                session,
                "recovery.denied",
                user["username"],
                {"request_id": request_id, "reason": "recovery_frozen"},
            )
            session.commit()
            raise HTTPException(status_code=423, detail="recovery is frozen")
        epoch = session.get(EpochRow, recovery.epoch_id)
        assert epoch is not None
        try:
            dek = runtime.recover_dek(recovery.vault_id, epoch, request_id)
            plaintext = runtime._decrypt_epoch(epoch, dek)
        except Exception as exc:
            recovery.status = "FAILED"
            runtime.audit(
                session,
                "recovery.denied",
                user["username"],
                {"request_id": request_id, "reason": str(exc)[:120]},
            )
            session.commit()
            raise HTTPException(
                status_code=503, detail="recovery failed closed: insufficient valid shares"
            ) from exc
        recovery.status = "COMPLETED"
        recovery.received_shares = recovery.required_shares
        runtime.audit(
            session,
            "recovery.completed",
            user["username"],
            {
                "request_id": request_id,
                "vault_id": recovery.vault_id,
                "epoch_id": recovery.epoch_id,
            },
        )
        return {
            "id": request_id,
            "status": "COMPLETED",
            "filename": epoch.filename,
            "content_base64": _b64(plaintext),
            "received_shares": recovery.received_shares,
        }


@app.get("/nodes")
def list_nodes(user: dict[str, str] = Depends(current_user)) -> list[dict[str, object]]:
    scores, _ = runtime.risk.scores()
    result = []
    for node in runtime.nodes:
        details = node.health()
        details["risk_score"] = scores.get(f"node-{node.node_id}", 0)
        details["invalid_responses"] = runtime.node_errors[node.node_id]
        details["signing_key_fingerprint"] = hashlib.sha256(
            node.public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ).hexdigest()[:16]
        result.append(details)
    return result


@app.get("/nodes/{node_id}")
def get_node(node_id: int, user: dict[str, str] = Depends(current_user)) -> dict[str, object]:
    if node_id < 1 or node_id > 5:
        raise HTTPException(status_code=404, detail="node not found")
    node = runtime.nodes[node_id - 1]
    score = runtime.risk.scores()[0].get(f"node-{node_id}", 0)
    return node.health() | {"risk_score": score, "invalid_responses": runtime.node_errors[node_id]}


@app.get("/nodes/{node_id}/health")
def node_health(node_id: int, user: dict[str, str] = Depends(current_user)) -> dict[str, object]:
    return get_node(node_id, user)


@app.get("/risk/current")
def risk_current(user: dict[str, str] = Depends(current_user)) -> dict[str, object]:
    nodes, overall = runtime.risk.scores()
    target = runtime.quorum.profile_for_score(overall)
    return {
        "overall_score": overall,
        "target_level": target.level.value,
        "target_threshold": target.threshold,
        "active_threshold": runtime.quorum.state.active_threshold,
        "recovery_frozen": runtime.quorum.state.recovery_frozen,
        "node_scores": nodes,
        "explanations": [
            item.__dict__ | {"kind": item.kind.value} for item in runtime.risk.explain()
        ],
    }


@app.get("/risk/history")
def risk_history(user: dict[str, str] = Depends(current_user)) -> list[dict[str, object]]:
    return [
        {
            "event_id": item.event_id,
            "kind": item.kind.value,
            "effective_points": item.effective_points,
            "age_seconds": item.age_seconds,
        }
        for item in runtime.risk.explain()
    ]


@app.post("/simulator/attacks")
async def simulate_attack(
    body: AttackBody, user: dict[str, str] = Depends(require_admin)
) -> dict[str, object]:
    if body.take_node_offline:
        runtime.set_node_online(body.node_id, False)
    event = RiskEvent(
        str(uuid.uuid4()),
        f"node-{body.node_id}",
        body.kind,
        datetime.now(UTC),
        body.critical,
    )
    with SessionLocal.begin() as session:
        runtime.record_risk_event(session, event)
        scores, overall = runtime.risk.scores()
        profile = runtime.quorum.request_transition(overall, critical=body.critical)
        runtime.audit(
            session,
            "simulator.attack",
            user["username"],
            {
                "event_id": event.event_id,
                "node_id": body.node_id,
                "kind": body.kind.value,
                "critical": body.critical,
            },
        )
    rotated: list[str] = []
    if profile is not None:
        with SessionLocal() as session:
            active_rows = session.scalars(
                select(VaultRow).where(VaultRow.active_epoch_id.is_not(None))
            ).all()
            needs_rotation = []
            for row in active_rows:
                current_epoch = session.get(EpochRow, row.active_epoch_id)
                if current_epoch and current_epoch.threshold != profile.threshold:
                    needs_rotation.append(row.id)
        for vault_id in needs_rotation:
            try:
                response = await rotate_vault(
                    vault_id,
                    RotateBody(threshold=profile.threshold, finish_policy_transition=False),
                    {"username": user["username"], "role": "admin"},
                )
                rotated.append(str(response["id"]))
            except HTTPException:
                break
        if len(rotated) == len(needs_rotation):
            runtime.quorum.complete_transition(
                new_epoch=rotated[0] if rotated else f"policy-{uuid.uuid4()}", success=True
            )
    await hub.publish(
        {
            "type": "risk.updated",
            "node_id": body.node_id,
            "overall_score": overall,
            "threshold": runtime.quorum.state.active_threshold,
        }
    )
    return {
        "event_id": event.event_id,
        "node_scores": scores,
        "overall_score": overall,
        "target_threshold": profile.threshold if profile else runtime.quorum.state.active_threshold,
        "active_threshold": runtime.quorum.state.active_threshold,
        "rotated_epochs": rotated,
        "simulation": True,
    }


@app.post("/simulator/reset")
def reset_simulation(user: dict[str, str] = Depends(require_admin)) -> dict[str, str]:
    for node in runtime.nodes:
        runtime.set_node_online(node.node_id, True)
    runtime.node_errors = {i: 0 for i in range(1, 6)}
    with SessionLocal.begin() as session:
        runtime.clear_risk_history(session)
        runtime.audit(session, "simulator.reset", user["username"], {})
    return {
        "status": "reset",
        "note": (
            "risk events and node error counters cleared; vaults, epochs, and "
            "audit records were retained"
        ),
    }


@app.get("/simulator/scenarios")
def scenarios(user: dict[str, str] = Depends(current_user)) -> list[dict[str, object]]:
    return [
        {"kind": kind.value, "default_points": runtime.risk._weights.get(kind, 0)}
        for kind in EventKind
    ]


@app.post("/trace-cases")
def create_trace_case(
    body: TraceBody, user: dict[str, str] = Depends(require_admin)
) -> dict[str, object]:
    with SessionLocal.begin() as session:
        vault = session.get(VaultRow, body.vault_id)
        if vault is None:
            raise HTTPException(status_code=404, detail="vault not found")
        epoch_id = body.epoch_id or vault.active_epoch_id
        epoch = session.get(EpochRow, epoch_id) if epoch_id else None
        if epoch is None or epoch.vault_id != vault.id:
            raise HTTPException(status_code=404, detail="vault epoch not found")
        if len(set(body.leaked_node_ids)) != len(body.leaked_node_ids):
            raise HTTPException(status_code=422, detail="leaked node IDs must be distinct")
        if len(body.leaked_node_ids) >= epoch.threshold:
            raise HTTPException(
                status_code=422,
                detail="traceability requires fewer leaked shares than the threshold",
            )
        context = runtime.trace_contexts.get(epoch.id)
        if context is None:
            raise HTTPException(
                status_code=503,
                detail="private tracing context is unavailable after service restart",
            )
        fixed: list[ShareholderShare] = []
        for node_id in body.leaked_node_ids:
            if node_id < 1 or node_id > 5:
                raise HTTPException(status_code=422, detail="node ID must be between 1 and 5")
            raw = runtime.nodes[node_id - 1].simulated_compromised_share(vault.id, epoch.id)
            if raw is None:
                raise HTTPException(
                    status_code=404, detail=f"node-{node_id} has no available share for this epoch"
                )
            if not isinstance(raw, dict):
                raise HTTPException(status_code=422, detail="malformed node share")
            raw_index = raw.get("index")
            raw_modulus = raw.get("modulus")
            raw_residues = raw.get("residues")
            if (
                not isinstance(raw_index, (int, str))
                or not isinstance(raw_modulus, (int, str))
                or not isinstance(raw_residues, list)
                or not all(isinstance(item, (int, str)) for item in raw_residues)
            ):
                raise HTTPException(status_code=422, detail="malformed node share fields")
            fixed.append(
                ShareholderShare(
                    int(raw_index),
                    int(raw_modulus),
                    tuple(int(item) for item in raw_residues),
                )
            )
        box = EmbeddedShareBox(context.parameters, int(epoch.a1), fixed)
        result = trace_ii(context, box, len(fixed), max_queries=256)
        if result is None:
            raise HTTPException(
                status_code=422, detail="tracing box did not yield a verifiable result"
            )
        identified, proof = result
        verified = verify_ii(context, identified, proof)
        row = TraceCaseRow(
            id=str(uuid.uuid4()),
            vault_id=vault.id,
            epoch_id=epoch.id,
            leaked_nodes_json=json.dumps(sorted(body.leaked_node_ids)),
            identified_nodes_json=json.dumps(sorted(identified)),
            proof_integer=str(proof),
            verified=verified,
        )
        session.add(row)
        runtime.audit(
            session,
            "trace.completed",
            user["username"],
            {
                "case_id": row.id,
                "vault_id": vault.id,
                "epoch_id": epoch.id,
                "identified_nodes": sorted(identified),
                "verified": verified,
            },
        )
        return {
            "id": row.id,
            "vault_id": vault.id,
            "epoch_id": epoch.id,
            "leaked_nodes": sorted(body.leaked_node_ids),
            "identified_nodes": sorted(identified),
            "proof": str(proof),
            "verified": verified,
            "mode": "simulated-compromise-box",
        }


@app.get("/trace-cases/{case_id}")
def get_trace_case(case_id: str, user: dict[str, str] = Depends(current_user)) -> dict[str, object]:
    with SessionLocal() as session:
        row = session.get(TraceCaseRow, case_id)
        if row is None:
            raise HTTPException(status_code=404, detail="trace case not found")
        return {
            "id": row.id,
            "vault_id": row.vault_id,
            "epoch_id": row.epoch_id,
            "leaked_nodes": json.loads(row.leaked_nodes_json),
            "identified_nodes": json.loads(row.identified_nodes_json),
            "proof": row.proof_integer,
            "verified": row.verified,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }


@app.post("/trace-cases/{case_id}/verify")
def verify_trace_case(
    case_id: str, user: dict[str, str] = Depends(current_user)
) -> dict[str, object]:
    with SessionLocal() as session:
        row = session.get(TraceCaseRow, case_id)
        if row is None:
            raise HTTPException(status_code=404, detail="trace case not found")
        context = runtime.trace_contexts.get(row.epoch_id)
        if context is None:
            raise HTTPException(status_code=503, detail="verification context is unavailable")
        identified = frozenset(int(x) for x in json.loads(row.identified_nodes_json))
        valid = verify_ii(context, identified, int(row.proof_integer))
        return {"id": row.id, "valid": valid}


@app.get("/dashboard")
def dashboard(user: dict[str, str] = Depends(current_user)) -> dict[str, object]:
    node_scores, overall = runtime.risk.scores()
    with SessionLocal() as session:
        vaults = session.scalars(select(VaultRow)).all()
        pending = len(
            session.scalars(select(RecoveryRow).where(RecoveryRow.status == "PENDING")).all()
        )
        recent = session.scalars(
            select(AuditRow).order_by(AuditRow.sequence.desc()).limit(10)
        ).all()
        audit_events = [
            {
                "id": row.sequence,
                "type": row.event_type,
                "actor": row.actor,
                "created_at": row.occurred_at.isoformat(),
            }
            for row in reversed(recent)
        ]
        active_epochs = [
            session.get(EpochRow, item.active_epoch_id) for item in vaults if item.active_epoch_id
        ]
        return {
            "overall_risk": overall,
            "target_quorum": runtime.quorum.profile_for_score(overall).threshold,
            "active_quorum": runtime.quorum.state.active_threshold,
            "active_epoch_count": len(active_epochs),
            "vault_count": len(vaults),
            "pending_recoveries": pending,
            "recovery_frozen": runtime.quorum.state.recovery_frozen,
            "node_scores": node_scores,
            "nodes": [node.health() for node in runtime.nodes],
            "recent_events": audit_events,
        }


@app.get("/audit")
def audit_events(user: dict[str, str] = Depends(current_user)) -> dict[str, object]:
    with SessionLocal() as session:
        rows = session.scalars(select(AuditRow).order_by(AuditRow.sequence)).all()
        return {
            "verified": runtime.verify_audit(rows),
            "events": [
                {
                    "id": row.sequence,
                    "type": row.event_type,
                    "actor": row.actor,
                    "payload": json.loads(row.payload_json),
                    "hash": row.record_hash,
                    "previous_hash": row.previous_hash,
                    "created_at": row.occurred_at.isoformat(),
                }
                for row in rows
            ],
        }


@app.get("/audit/verify")
def verify_audit(user: dict[str, str] = Depends(current_user)) -> dict[str, bool]:
    with SessionLocal() as session:
        rows = session.scalars(select(AuditRow).order_by(AuditRow.sequence)).all()
        return {"valid": runtime.verify_audit(rows)}


@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket, token: str) -> None:
    try:
        _read_auth_token(token)
    except HTTPException:
        await websocket.close(code=4401)
        return
    await websocket.accept()
    queue: asyncio.Queue[dict[str, object]] = asyncio.Queue(maxsize=32)
    hub.connections.add(queue)
    try:
        await websocket.send_json({"type": "connected"})
        while True:
            event = await queue.get()
            await websocket.send_json(event)
    except WebSocketDisconnect:
        pass
    finally:
        hub.connections.discard(queue)
