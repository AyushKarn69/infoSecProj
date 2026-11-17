from dataclasses import replace
from datetime import UTC, datetime, timedelta

from core.audit.hash_chain import HashChain
from core.quorum_manager.policy import QuorumManager, RiskLevel
from core.risk_engine.engine import EventKind, RiskEngine, RiskEvent

NOW = datetime(2026, 11, 13, tzinfo=UTC)


def test_risk_scores_are_explainable_deduplicated_and_decay() -> None:
    engine = RiskEngine(decay_after=timedelta(hours=2))
    event = RiskEvent("evt-1", "node-1", EventKind.INVALID_SHARE, NOW)
    assert engine.record(event)
    assert not engine.record(event)
    node_scores, overall = engine.scores(now=NOW)
    assert node_scores == {"node-1": 30}
    assert overall == 30
    assert engine.explain(now=NOW)[0].effective_points == 30
    decayed, overall = engine.scores(now=NOW + timedelta(hours=1))
    assert decayed == {"node-1": 15}
    assert overall == 15
    assert engine.scores(now=NOW + timedelta(hours=3)) == ({"node-1": 0}, 0)


def test_critical_event_and_rising_risk_start_epoch_transition_immediately() -> None:
    manager = QuorumManager(cooldown=timedelta(hours=1))
    target = manager.request_transition(15, now=NOW, critical=True)
    assert target is not None and target.level == RiskLevel.HIGH and target.threshold == 4
    assert not manager.recovery_allowed
    manager.complete_transition(new_epoch="epoch-2", success=True)
    assert manager.recovery_allowed
    assert manager.state.active_threshold == 4
    assert manager.request_transition(35, now=NOW + timedelta(seconds=1)) is None
    assert manager.state.transition_target is None


def test_lower_threshold_requires_admin_and_cooldown_then_new_epoch() -> None:
    manager = QuorumManager(cooldown=timedelta(minutes=30))
    manager.request_transition(60, now=NOW)
    manager.complete_transition(new_epoch="epoch-2", success=True)
    assert manager.request_transition(10, now=NOW + timedelta(hours=1)) is None
    assert (
        manager.request_transition(10, now=NOW + timedelta(hours=1), administrator_authorized=True)
        is None
    )
    assert (
        manager.request_transition(
            10, now=NOW + timedelta(hours=1, minutes=29), administrator_authorized=True
        )
        is None
    )
    target = manager.request_transition(
        10, now=NOW + timedelta(hours=1, minutes=30), administrator_authorized=True
    )
    assert target is not None and target.threshold == 2
    manager.complete_transition(new_epoch="epoch-3", success=True)
    assert manager.state.active_epoch == "epoch-3"
    assert manager.state.active_threshold == 2


def test_failed_epoch_transition_keeps_the_active_quorum() -> None:
    manager = QuorumManager()
    manager.request_transition(70, now=NOW)
    state = manager.complete_transition(new_epoch="unused", success=False)
    assert state.active_epoch == "epoch-1"
    assert state.active_threshold == 2
    assert state.transition_target is not None and state.transition_target.threshold == 4
    assert state.recovery_frozen
    assert not manager.recovery_allowed


def test_audit_hash_chain_detects_record_tampering() -> None:
    log = HashChain()
    first = log.append("recovery.started", "admin", {"vault": "v1"}, occurred_at=NOW)
    log.append("recovery.denied", "system", {"reason": "quorum"}, occurred_at=NOW)
    assert first.sequence == 1
    assert log.verify()
    log._records[0] = replace(first, actor="attacker")
    assert not log.verify()
