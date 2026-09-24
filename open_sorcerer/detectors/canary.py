"""CanaryDetector: confirm no active canary token leaked into output."""

from __future__ import annotations

from ..canary import Canary
from .base import BaseDetector, DetectorResult, Severity


class CanaryDetector(BaseDetector):
    """Machine-check that no active canary token leaked into the text."""

    name = "canary"

    def __init__(self, canary: Canary | None = None, token_length: int = 32) -> None:
        self._canary = canary or Canary()
        self._token_length = token_length

    @property
    def canary(self) -> Canary:
        return self._canary

    def issue(self) -> str:
        return self._canary.issue(self._token_length)

    def scan(self, text: str, **kwargs: object) -> DetectorResult:
        leaked = self._canary.check(text, normalize=True)
        if not leaked:
            return DetectorResult(
                detector=self.name,
                flagged=False,
                severity=Severity.INFO,
                findings=[],
            )
        active = self._canary.active
        leaked_tokens = [
            t for t in active
            if t in text or t.replace(" ", "") in text.replace(" ", "")
        ]
        return DetectorResult(
            detector=self.name,
            flagged=True,
            severity=Severity.CRITICAL,
            score=1.0,
            confidence=1.0,
            findings=[f"canary leaked: {tok[:8]}..." for tok in leaked_tokens],
        )
