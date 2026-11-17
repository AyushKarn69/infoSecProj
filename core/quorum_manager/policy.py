"""Threshold policy that changes only after a new epoch is activated."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class Profile:
    level: RiskLevel
    threshold: int


DEFAULT_PROFILES = (
    Profile(RiskLevel.LOW, 2),
    Profile(RiskLevel.MEDIUM, 3),
    Profile(RiskLevel.HIGH, 4),
)


@dataclass(frozen=True)
class QuorumState:
    active_level: RiskLevel
    active_threshold: int
    active_epoch: str
    transition_target: Profile | None = None
    transition_started_at: datetime | None = None
    recovery_frozen: bool = False


class QuorumManager:
    def __init__(self, *, n: int = 5, cooldown: timedelta = timedelta(hours=1)) -> None:
        if n < 1 or cooldown.total_seconds() < 0:
            raise ValueError("invalid n or cooldown")
        if any(profile.threshold > n for profile in DEFAULT_PROFILES):
            raise ValueError("configured quorum exceeds node count")
        self.n = n
        self.cooldown = cooldown
        self._state = QuorumState(RiskLevel.LOW, 2, "epoch-1")
        self._transition_ready = False

    @property
    def state(self) -> QuorumState:
        return self._state

    @property
    def recovery_allowed(self) -> bool:
        return not self._state.recovery_frozen

    @staticmethod
    def profile_for_score(score: int) -> Profile:
        if not 0 <= score <= 100:
            raise ValueError("risk score must be in [0, 100]")
        if score < 30:
            return DEFAULT_PROFILES[0]
        if score < 60:
            return DEFAULT_PROFILES[1]
        return DEFAULT_PROFILES[2]

    def request_transition(
        self,
        score: int,
        *,
        now: datetime | None = None,
        critical: bool = False,
        administrator_authorized: bool = False,
    ) -> Profile | None:
        now = now or datetime.now(UTC)
        if now.tzinfo is None:
            raise ValueError("now must be timezone aware")
        target = self.profile_for_score(score)
        if critical:
            target = DEFAULT_PROFILES[2]
        current_rank = list(RiskLevel).index(self._state.active_level)
        target_rank = list(RiskLevel).index(target.level)
        if self._state.transition_target is not None:
            if target.threshold == self._state.active_threshold:
                self._state = QuorumState(
                    self._state.active_level, self._state.active_threshold, self._state.active_epoch
                )
                self._transition_ready = False
                return None
            if self._transition_ready:
                return self._state.transition_target
            pending = self._state.transition_target
            if target_rank > current_rank:
                # A rising risk cancels any cooldown and escalates immediately.
                self._state = QuorumState(
                    self._state.active_level,
                    self._state.active_threshold,
                    self._state.active_epoch,
                    transition_target=target,
                    transition_started_at=now,
                    recovery_frozen=True,
                )
                self._transition_ready = True
                return target
            if not administrator_authorized or target != pending:
                return None
            if now - (self._state.transition_started_at or now) < self.cooldown:
                return None
            self._state = QuorumState(
                self._state.active_level,
                self._state.active_threshold,
                self._state.active_epoch,
                transition_target=pending,
                transition_started_at=self._state.transition_started_at,
                recovery_frozen=True,
            )
            self._transition_ready = True
            return pending
        if target.threshold == self._state.active_threshold:
            return None
        is_escalation = target_rank > current_rank
        if not is_escalation:
            if not administrator_authorized:
                return None
            # Caller supplies the time at which risk decreased; a cooldown starts
            # from this policy observation and must elapse before transition.
            if self._state.transition_started_at is None:
                self._state = QuorumState(
                    self._state.active_level,
                    self._state.active_threshold,
                    self._state.active_epoch,
                    transition_target=target,
                    transition_started_at=now,
                )
                return None
            if now - self._state.transition_started_at < self.cooldown:
                return None
        # Escalation, especially a confirmed critical event, is immediate.
        self._state = QuorumState(
            self._state.active_level,
            self._state.active_threshold,
            self._state.active_epoch,
            transition_target=target,
            transition_started_at=now,
            recovery_frozen=True,
        )
        self._transition_ready = is_escalation or critical
        if not self._transition_ready:
            return None
        return target

    def complete_transition(self, *, new_epoch: str, success: bool) -> QuorumState:
        target = self._state.transition_target
        if target is None:
            raise ValueError("no epoch transition is pending")
        if not success:
            self._state = QuorumState(
                self._state.active_level,
                self._state.active_threshold,
                self._state.active_epoch,
                transition_target=target,
                transition_started_at=self._state.transition_started_at,
                recovery_frozen=True,
            )
            self._transition_ready = False
            return self._state
        if not new_epoch or new_epoch == self._state.active_epoch:
            raise ValueError("successful transition requires a fresh epoch identifier")
        self._state = QuorumState(target.level, target.threshold, new_epoch, recovery_frozen=False)
        self._transition_ready = False
        return self._state

    def restore_active_policy(
        self,
        threshold: int,
        *,
        recovery_frozen: bool = False,
        transition_target_threshold: int | None = None,
    ) -> QuorumState:
        profiles = {profile.threshold: profile for profile in DEFAULT_PROFILES}
        if threshold not in profiles:
            raise ValueError("restored threshold is not configured")
        profile = profiles[threshold]
        target = (
            profiles.get(transition_target_threshold)
            if transition_target_threshold is not None
            else None
        )
        if target is not None and target.threshold <= threshold:
            target = None
        self._state = QuorumState(
            profile.level,
            threshold,
            "restored",
            transition_target=target,
            transition_started_at=datetime.now(UTC) if target else None,
            recovery_frozen=recovery_frozen,
        )
        self._transition_ready = target is not None
        return self._state

    def confirm_all_vaults_at_active_threshold(self) -> QuorumState:
        if self._state.transition_target is None:
            self._state = QuorumState(
                self._state.active_level, self._state.active_threshold, self._state.active_epoch
            )
        return self._state
