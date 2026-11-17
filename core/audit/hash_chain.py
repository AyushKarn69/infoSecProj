"""In-memory append-only hash chain for audit events."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime

GENESIS = "0" * 64


@dataclass(frozen=True)
class AuditRecord:
    sequence: int
    occurred_at: str
    event_type: str
    actor: str
    payload: dict[str, str | int | bool | None]
    previous_hash: str
    record_hash: str


class HashChain:
    def __init__(self) -> None:
        self._records: list[AuditRecord] = []

    @property
    def records(self) -> tuple[AuditRecord, ...]:
        return tuple(self._records)

    def append(
        self,
        event_type: str,
        actor: str,
        payload: dict[str, str | int | bool | None],
        *,
        occurred_at: datetime | None = None,
    ) -> AuditRecord:
        if not event_type or not actor:
            raise ValueError("event_type and actor are required")
        timestamp = occurred_at or datetime.now(UTC)
        if timestamp.tzinfo is None:
            raise ValueError("occurred_at must be timezone aware")
        sequence = len(self._records) + 1
        previous = self._records[-1].record_hash if self._records else GENESIS
        occurred = timestamp.astimezone(UTC).isoformat()
        body = {
            "sequence": sequence,
            "occurred_at": occurred,
            "event_type": event_type,
            "actor": actor,
            "payload": payload,
            "previous_hash": previous,
        }
        record_hash = hashlib.sha256(_canonical(body)).hexdigest()
        record = AuditRecord(
            sequence, occurred, event_type, actor, dict(payload), previous, record_hash
        )
        self._records.append(record)
        return record

    def verify(self) -> bool:
        previous = GENESIS
        for sequence, record in enumerate(self._records, start=1):
            if record.sequence != sequence or record.previous_hash != previous:
                return False
            body = {
                "sequence": record.sequence,
                "occurred_at": record.occurred_at,
                "event_type": record.event_type,
                "actor": record.actor,
                "payload": record.payload,
                "previous_hash": record.previous_hash,
            }
            if hashlib.sha256(_canonical(body)).hexdigest() != record.record_hash:
                return False
            previous = record.record_hash
        return True


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )
