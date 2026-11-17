"""Deterministic, explainable risk scoring with event deduplication and decay."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum


class EventKind(StrEnum):
    FAILED_AUTHENTICATION = "failed_authentication"
    ABNORMAL_REQUEST_BURST = "abnormal_request_burst"
    INVALID_SHARE = "invalid_share"
    INVALID_NODE_SIGNATURE = "invalid_node_signature"
    MISSED_HEARTBEAT = "missed_heartbeat"
    SUSPICIOUS_RECOVERY = "suspicious_recovery"
    FAILED_RECOVERY = "failed_recovery"
    SHARE_INTEGRITY_FAILURE = "share_integrity_failure"


DEFAULT_WEIGHTS: dict[EventKind, int] = {
    EventKind.FAILED_AUTHENTICATION: 15,
    EventKind.ABNORMAL_REQUEST_BURST: 20,
    EventKind.INVALID_SHARE: 30,
    EventKind.INVALID_NODE_SIGNATURE: 40,
    EventKind.MISSED_HEARTBEAT: 15,
    EventKind.SUSPICIOUS_RECOVERY: 20,
    EventKind.FAILED_RECOVERY: 15,
    EventKind.SHARE_INTEGRITY_FAILURE: 30,
}


@dataclass(frozen=True)
class RiskEvent:
    event_id: str
    node_id: str
    kind: EventKind
    occurred_at: datetime
    critical: bool = False


@dataclass(frozen=True)
class RiskContribution:
    event_id: str
    kind: EventKind
    raw_points: int
    effective_points: int
    age_seconds: float


class RiskEngine:
    """Scores events with linear time decay; critical events may escalate now."""

    def __init__(
        self,
        *,
        weights: dict[EventKind, int] | None = None,
        decay_after: timedelta = timedelta(hours=24),
    ) -> None:
        if decay_after.total_seconds() <= 0:
            raise ValueError("decay_after must be positive")
        self._weights = dict(DEFAULT_WEIGHTS if weights is None else weights)
        if any(points < 0 for points in self._weights.values()):
            raise ValueError("risk weights cannot be negative")
        self._decay_after = decay_after
        self._events: dict[str, RiskEvent] = {}

    def record(self, event: RiskEvent) -> bool:
        """Record once by event ID; return False when the event was a duplicate."""
        if not event.event_id or not event.node_id:
            raise ValueError("event_id and node_id are required")
        if event.event_id in self._events:
            return False
        if event.occurred_at.tzinfo is None:
            raise ValueError("occurred_at must be timezone aware")
        self._events[event.event_id] = event
        return True

    def scores(self, *, now: datetime | None = None) -> tuple[dict[str, int], int]:
        now = now or datetime.now(UTC)
        if now.tzinfo is None:
            raise ValueError("now must be timezone aware")
        contributions = self._contributions(now)
        totals: dict[str, int] = {}
        for event in self._events.values():
            totals.setdefault(event.node_id, 0)
        for node_id in totals:
            points = sum(
                item.effective_points
                for item in contributions
                if self._events[item.event_id].node_id == node_id
            )
            totals[node_id] = min(100, points)
        overall = min(100, sum(totals.values()))
        return totals, overall

    def explain(self, *, now: datetime | None = None) -> tuple[RiskContribution, ...]:
        return tuple(
            sorted(
                self._contributions(now or datetime.now(UTC)),
                key=lambda item: (-item.effective_points, item.event_id),
            )
        )

    def has_active_critical_event(self, *, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        return any(
            event.critical and self._effective_points(event, now) > 0
            for event in self._events.values()
        )

    def _contributions(self, now: datetime) -> list[RiskContribution]:
        items: list[RiskContribution] = []
        for event in self._events.values():
            raw = self._weights.get(event.kind, 0)
            age = max(0.0, (now - event.occurred_at).total_seconds())
            fraction = max(0.0, 1.0 - age / self._decay_after.total_seconds())
            items.append(
                RiskContribution(event.event_id, event.kind, raw, round(raw * fraction), age)
            )
        return items

    def _effective_points(self, event: RiskEvent, now: datetime) -> int:
        age = max(0.0, (now - event.occurred_at).total_seconds())
        fraction = max(0.0, 1.0 - age / self._decay_after.total_seconds())
        return round(self._weights.get(event.kind, 0) * fraction)
