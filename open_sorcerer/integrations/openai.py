from __future__ import annotations

from ..detector import DetectionResult, Detector
from ..errors import SecurityError


def _extract_text(input_data) -> str:
    if isinstance(input_data, str):
        return input_data
    return str(input_data)


class SecureResponses:
    def __init__(self, client, detector: Detector):
        self._client = client
        self._detector = detector

    def create(self, **kwargs):
        input_data = kwargs.get("input")
        result = self._detector.scan(_extract_text(input_data))
        if result.blocked:
            raise SecurityError(result.reason or "Request blocked by security policy.")
        return self._client.responses.create(**kwargs)


class SecureOpenAI:
    def __init__(self, client, detector: Detector):
        self._client = client
        self._detector = detector
        self.responses = SecureResponses(client, detector)


class DetectorAdapter:
    def __init__(self, detector):
        self._detector = detector

    def scan(self, text: str) -> DetectionResult:
        result = self._detector.scan(text)
        blocked = bool(getattr(result, "blocked", False) or getattr(result, "flagged", False))
        severity = getattr(result, "severity", None)
        if not blocked and severity is not None:
            try:
                from open_sorcerer.detectors import Severity
                blocked = severity >= Severity.HIGH
            except ImportError:
                pass
        findings = getattr(result, "findings", []) or []
        attack_type = findings[0] if findings else None
        summary = getattr(result, "summary", "") or ""
        return DetectionResult(
            blocked=blocked,
            score=float(getattr(result, "score", 0.0) or 0.0),
            attack_type=attack_type,
            reason=summary or None,
        )
