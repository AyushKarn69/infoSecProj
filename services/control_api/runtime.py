"""Control-plane orchestration for vaults, nodes, risk and audit."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from core.audit.hash_chain import GENESIS
from core.crypto.abss.abss_i import ABSSParameters, ShareholderShare, reconstruct
from core.crypto.encryption.aes_gcm import (
    EncryptedObject,
    decrypt,
    dek_to_integer,
    encrypt,
    generate_dek,
    integer_to_dek,
)
from core.crypto.ttss.ttss_ii import TTSSIIShareSet, share_ii
from core.quorum_manager.policy import QuorumManager
from core.risk_engine.engine import EventKind, RiskEngine, RiskEvent
from services.control_api.db import (
    AuditRow,
    EpochRow,
    RiskEventRow,
    VaultRow,
)
from services.control_api.node_client import RemoteNodeClient
from services.node_agent.agent import NodeAgent, canonical, issue_release_token


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class Runtime:
    def __init__(self) -> None:
        self.base = Path(os.getenv("RISKSHARE_DATA_DIR", "./data"))
        self.base.mkdir(parents=True, exist_ok=True)
        self.control_secret = os.getenv(
            "RISKSHARE_CONTROL_SECRET", "development-only-change-me"
        ).encode("utf-8")
        node_urls = [
            url.strip() for url in os.getenv("RISKSHARE_NODE_URLS", "").split(",") if url.strip()
        ]
        self.nodes: list[NodeAgent | RemoteNodeClient]
        if node_urls:
            if len(node_urls) != 5:
                raise RuntimeError("RISKSHARE_NODE_URLS must contain exactly five node URLs")
            self.nodes = [
                RemoteNodeClient(
                    i,
                    url,
                    self.control_secret,
                    ca_file=os.getenv("RISKSHARE_NODE_CA", "./certs/ca.pem"),
                    client_cert=os.getenv(
                        "RISKSHARE_CONTROL_CLIENT_CERT", "./certs/control-api.pem"
                    ),
                    client_key=os.getenv(
                        "RISKSHARE_CONTROL_CLIENT_KEY", "./certs/control-api-key.pem"
                    ),
                )
                for i, url in enumerate(node_urls, start=1)
            ]
        else:
            self.nodes = [
                NodeAgent(i, self.base / "nodes" / f"node-{i}.sqlite3", self.control_secret)
                for i in range(1, 6)
            ]
        self.risk = RiskEngine()
        self.quorum = QuorumManager(n=5)
        self.trace_keys: dict[str, object] = {}
        self.trace_contexts: dict[str, TTSSIIShareSet] = {}
        self.node_errors: dict[int, int] = {i: 0 for i in range(1, 6)}

    def set_node_online(self, node_id: int, online: bool) -> bool:
        node = self.nodes[node_id - 1]
        if isinstance(node, NodeAgent):
            node.set_online(online)
            return True
        return node.set_online(online)

    def load_risk_history(self, session: Session) -> None:
        self.risk = RiskEngine()
        for row in session.scalars(select(RiskEventRow).order_by(RiskEventRow.occurred_at)).all():
            occurred = (
                row.occurred_at.replace(tzinfo=UTC)
                if row.occurred_at.tzinfo is None
                else row.occurred_at
            )
            self.risk.record(
                RiskEvent(row.event_id, row.node_id, EventKind(row.kind), occurred, row.critical)
            )

    def restore_policy(self, session: Session) -> None:
        active = session.scalars(select(EpochRow).where(EpochRow.status == "ACTIVE")).all()
        thresholds = {row.threshold for row in active}
        interrupted_rows = session.scalars(
            select(EpochRow).where(EpochRow.status == "DISTRIBUTING")
        ).all()
        pending_thresholds = [row.threshold for row in interrupted_rows]
        for row in active:
            failed_rows = session.scalars(
                select(EpochRow).where(
                    EpochRow.vault_id == row.vault_id,
                    EpochRow.status == "FAILED",
                    EpochRow.created_at > row.created_at,
                    EpochRow.threshold > row.threshold,
                )
            ).all()
            pending_thresholds.extend(item.threshold for item in failed_rows)
        threshold = min(thresholds) if thresholds else 2
        pending_target = max([*thresholds, *pending_thresholds], default=threshold)
        frozen = bool(interrupted_rows or pending_thresholds or len(thresholds) > 1)
        self.quorum.restore_active_policy(
            threshold,
            recovery_frozen=frozen,
            transition_target_threshold=pending_target if frozen else None,
        )

    def record_risk_event(self, session: Session, event: RiskEvent) -> bool:
        if not self.risk.record(event):
            return False
        session.add(
            RiskEventRow(
                event_id=event.event_id,
                node_id=event.node_id,
                kind=event.kind.value,
                occurred_at=event.occurred_at.astimezone(UTC).replace(tzinfo=None),
                critical=event.critical,
            )
        )
        return True

    def clear_risk_history(self, session: Session) -> None:
        session.execute(delete(RiskEventRow))
        self.risk = RiskEngine()

    def audit(
        self,
        session: Session,
        event_type: str,
        actor: str,
        payload: dict[str, object],
    ) -> AuditRow:
        previous_row = session.scalar(select(AuditRow).order_by(AuditRow.sequence.desc()).limit(1))
        previous = previous_row.record_hash if previous_row else GENESIS
        timestamp = datetime.now(UTC).replace(tzinfo=None)
        body = {
            "sequence": (previous_row.sequence + 1) if previous_row else 1,
            "occurred_at": timestamp.isoformat(),
            "event_type": event_type,
            "actor": actor,
            "payload": payload,
            "previous_hash": previous,
        }
        digest = hashlib.sha256(canonical(body)).hexdigest()
        row = AuditRow(
            occurred_at=timestamp,
            event_type=event_type,
            actor=actor,
            payload_json=_json(payload),
            previous_hash=previous,
            record_hash=digest,
        )
        session.add(row)
        session.flush()
        return row

    def verify_audit(self, rows: Sequence[AuditRow]) -> bool:
        previous = GENESIS
        for sequence, row in enumerate(rows, 1):
            body = {
                "sequence": sequence,
                "occurred_at": row.occurred_at.isoformat(),
                "event_type": row.event_type,
                "actor": row.actor,
                "payload": json.loads(row.payload_json),
                "previous_hash": previous,
            }
            if (
                row.sequence != sequence
                or row.previous_hash != previous
                or hashlib.sha256(canonical(body)).hexdigest() != row.record_hash
            ):
                return False
            previous = row.record_hash
        return True

    def _serialize_share(self, share: ShareholderShare) -> dict[str, object]:
        return {
            "index": share.index,
            "modulus": str(share.modulus),
            "residues": [str(x) for x in share.residues],
        }

    def _distribute(
        self, vault_id: str, epoch_id: str, shares: tuple[ShareholderShare, ...]
    ) -> bool:
        acknowledgements = [
            node.distribute(vault_id, epoch_id, self._serialize_share(share))
            for node, share in zip(self.nodes, shares, strict=True)
        ]
        return all(acknowledgements)

    def _collect(self, vault_id: str, epoch: EpochRow, recovery_id: str) -> list[ShareholderShare]:
        parameters = ABSSParameters(
            n=epoch.n,
            threshold=epoch.threshold,
            m0=int(epoch.m0),
            moduli=tuple(int(x) for x in json.loads(epoch.moduli_json)),
            a1=int(epoch.a1),
        )
        parameters.validate()
        valid: list[ShareholderShare] = []
        for node in self.nodes:
            token = issue_release_token(self.control_secret, node.node_id, vault_id, epoch.id)
            response = node.release(token)
            if response is None:
                self.node_errors[node.node_id] += 1
                continue
            if (
                response.get("node_id") != node.node_id
                or response.get("vault_id") != vault_id
                or response.get("epoch_id") != epoch.id
            ):
                self.node_errors[node.node_id] += 1
                continue
            signature = base64.b64decode(str(response.pop("signature")))
            try:
                node.public_key.verify(signature, canonical(response))
            except Exception:
                self.node_errors[node.node_id] += 1
                continue
            raw = response["share"]
            if not isinstance(raw, dict):
                self.node_errors[node.node_id] += 1
                continue
            valid.append(
                ShareholderShare(
                    index=int(raw["index"]),
                    modulus=int(raw["modulus"]),
                    residues=tuple(int(x) for x in raw["residues"]),
                )
            )
            if len(valid) >= epoch.threshold:
                break
        return valid

    def _decrypt_epoch(self, epoch: EpochRow, dek: bytes) -> bytes:
        return decrypt(
            dek,
            EncryptedObject(
                vault_id=epoch.vault_id,
                epoch_id=epoch.id,
                encryption_version=epoch.encryption_version,
                nonce=epoch.nonce,
                ciphertext=epoch.ciphertext,
            ),
        )

    def recover_dek(self, vault_id: str, epoch: EpochRow, recovery_id: str) -> bytes:
        shares = self._collect(vault_id, epoch, recovery_id)
        if len(shares) < epoch.threshold:
            raise RuntimeError(
                f"insufficient valid node responses: {len(shares)}/{epoch.threshold}"
            )
        params = ABSSParameters(
            epoch.n,
            epoch.threshold,
            int(epoch.m0),
            tuple(int(x) for x in json.loads(epoch.moduli_json)),
            int(epoch.a1),
        )
        return integer_to_dek(reconstruct(params, shares))

    def create_epoch(
        self, session: Session, vault: VaultRow, plaintext: bytes, filename: str, threshold: int
    ) -> EpochRow:
        epoch_id = str(uuid.uuid4())
        dek = generate_dek()
        payload = encrypt(
            dek, plaintext, vault_id=vault.id, epoch_id=epoch_id, encryption_version=1
        )
        generation: TTSSIIShareSet = share_ii(dek_to_integer(dek), 5, threshold)
        row = EpochRow(
            id=epoch_id,
            vault_id=vault.id,
            status="DISTRIBUTING",
            threshold=threshold,
            n=5,
            m0=str(generation.parameters.m0),
            moduli_json=_json([str(x) for x in generation.parameters.moduli]),
            a1=str(generation.parameters.a1),
            nonce=payload.nonce,
            ciphertext=payload.ciphertext,
            filename=filename,
            encryption_version=1,
        )
        session.add(row)
        session.flush()
        if not self._distribute(vault.id, epoch_id, generation.shares):
            row.status = "FAILED"
            for node in self.nodes:
                node.retire_generation(vault.id, epoch_id)
            raise RuntimeError("all five nodes must acknowledge initial share distribution")
        row.status = "ACTIVE"
        self.trace_keys[epoch_id] = generation.tracing_key
        self.trace_contexts[epoch_id] = TTSSIIShareSet(
            parameters=generation.parameters,
            group=generation.group,
            shares=(),
            tracing_key=generation.tracing_key,
            verification_key=generation.verification_key,
        )
        return row


runtime = Runtime()
