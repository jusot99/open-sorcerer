"""Cross-request behavior detector: sustained / escalating abuse."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field

from .base import BaseDetector, DetectorResult, Severity


@dataclass
class _SessionProfile:
    total: int = 0
    weighted_score: float = 0.0
    flagged_times: list[float] = field(default_factory=list)
    request_times: list[float] = field(default_factory=list)


class BehaviorDetector(BaseDetector):
    """Escalate sustained flagged activity, per session or anonymous."""

    name: str = "behavior"
    session_aware: bool = True

    def __init__(
        self,
        max_flagged: int = 5,
        window_seconds: float = 60.0,
        max_sessions: int = 10000,
        max_rate: float = 30.0,
        weighted: bool = True,
    ) -> None:
        self._max_flagged = max_flagged
        self._window = window_seconds
        self._max_sessions = max_sessions
        self._max_rate = max_rate
        self._weighted = weighted
        self._lock = threading.RLock()
        self._sessions: OrderedDict[str, _SessionProfile] = OrderedDict()
        self._anonymous = _SessionProfile()
        self._anon_lock = threading.Lock()

    def _get_profile(self, session: str | None) -> _SessionProfile:
        if session is None:
            return self._anonymous
        with self._lock:
            if session not in self._sessions:
                self._sessions[session] = _SessionProfile()
                self._evict()
            self._sessions.move_to_end(session)
            return self._sessions[session]

    def _evict(self) -> None:
        while len(self._sessions) > self._max_sessions:
            self._sessions.popitem(last=False)

    def _prune(self, sp: _SessionProfile, now: float) -> None:
        cutoff = now - self._window
        sp.flagged_times = [t for t in sp.flagged_times if t > cutoff]
        sp.request_times = [t for t in sp.request_times if t > cutoff]

    def _severity_weight(self, severity: Severity) -> float:
        if not self._weighted:
            return 1.0
        return {
            Severity.INFO: 0.0,
            Severity.LOW: 0.5,
            Severity.MEDIUM: 1.0,
            Severity.HIGH: 2.0,
            Severity.CRITICAL: 4.0,
        }.get(severity, 1.0)

    def scan(self, text: str, **kwargs: object) -> DetectorResult:
        session = kwargs.get("session")
        if session is not None and not isinstance(session, str):
            session = None
        now = time.monotonic()

        if session is None:
            with self._anon_lock:
                sp = self._anonymous
                self._prune(sp, now)
                sp.request_times.append(now)
                count = len(sp.flagged_times)
                weighted = sp.weighted_score
        else:
            with self._lock:
                sp = self._get_profile(session)
                self._prune(sp, now)
                sp.request_times.append(now)
                count = len(sp.flagged_times)
                weighted = sp.weighted_score

        rate_rpm = self._rate_rpm(sp, now)
        sustained = count >= self._max_flagged
        rate_abuse = rate_rpm >= self._max_rate and count > 0
        weighted_threshold = float(self._max_flagged) * 1.5
        weighted_abuse = weighted >= weighted_threshold

        if sustained or rate_abuse or weighted_abuse:
            severity = Severity.CRITICAL if rate_abuse or weighted >= weighted_threshold * 1.5 else Severity.HIGH
            findings = ["sustained_flag_burst"]
            if rate_abuse:
                findings.append(f"high_rate_rpm={rate_rpm:.1f}")
            if weighted_abuse:
                findings.append(f"weighted_score={weighted:.1f}")
            return DetectorResult(
                detector=self.name,
                flagged=True,
                severity=severity,
                score=min(weighted, 100.0),
                confidence=min(0.95, 0.5 + count / 20),
                findings=findings,
            )
        return DetectorResult(detector=self.name, flagged=False)

    def note_flagged(self, session: str | None = None, severity: Severity = Severity.MEDIUM) -> None:
        """Called by the pipeline when any detector flags this session."""
        now = time.monotonic()
        weight = self._severity_weight(severity)
        if session is None:
            with self._anon_lock:
                sp = self._anonymous
                self._prune(sp, now)
                sp.flagged_times.append(now)
                sp.total += 1
                sp.weighted_score += weight
        else:
            with self._lock:
                sp = self._get_profile(session)
                self._prune(sp, now)
                sp.flagged_times.append(now)
                sp.total += 1
                sp.weighted_score += weight

    def _rate_rpm(self, sp: _SessionProfile, now: float) -> float:
        if not sp.request_times:
            return 0.0
        cutoff = now - 60.0
        recent = [t for t in sp.request_times if t > cutoff]
        return len(recent)

    def reset(self, session: str | None = None) -> None:
        if session is None:
            with self._anon_lock:
                self._anonymous = _SessionProfile()
        else:
            with self._lock:
                self._sessions.pop(session, None)

    @property
    def active_sessions(self) -> int:
        with self._lock:
            return len(self._sessions)
