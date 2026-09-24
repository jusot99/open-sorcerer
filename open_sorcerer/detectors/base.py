"""Base detector interface and shared types for open-sorcerer."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Severity ordering for detector findings. Higher = worse."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class DetectorResult:
    """Output of one detector on one input."""

    detector: str
    flagged: bool
    severity: Severity = Severity.INFO
    score: float = 0.0
    confidence: float = 1.0
    findings: list[str] = field(default_factory=list)
    normalized: str | None = None
    obfuscated: bool = False

    @property
    def summary(self) -> str:
        if not self.flagged:
            return f"[{self.detector}] clean"
        tags = ", ".join(self.findings) if self.findings else "unknown"
        return f"[{self.detector}] {self.severity.name} risk={self.score:.0f}: {tags}"


class BaseDetector:
    """Detector: text -> DetectorResult, stateless per scan."""

    name: str = "base"
    session_aware: bool = False

    def scan(self, text: str, **kwargs: object) -> DetectorResult:
        raise NotImplementedError

    def __repr__(self) -> str:  # pragma: no cover
        return f"<{type(self).__name__} {self.name}>"
