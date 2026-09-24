"""SecurityPipeline: config-driven, fail-fast detector runner."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import ClassVar

from .detectors import (
    AnomalyDetector,
    BaseDetector,
    BehaviorDetector,
    CanaryDetector,
    DetectorResult,
    PIIDetector,
    PromptInjectionDetector,
    Severity,
)

_AUDIT = logging.getLogger("open-sorcerer.audit")

@dataclass
class ScanResult:
    """Aggregated scan outcome for one text."""

    text: str
    results: list[DetectorResult] = field(default_factory=list)
    blocked: bool = False
    log: dict | None = None

    @property
    def flagged(self) -> bool:
        return any(r.flagged for r in self.results)

    @property
    def max_severity(self) -> Severity:
        if not self.results:
            return Severity.INFO
        return max(r.severity for r in self.results)

    @property
    def summary(self) -> str:
        if not self.flagged:
            return "OK"
        parts = []
        for r in self.results:
            if r.flagged:
                parts.append(r.summary)
        return " | ".join(parts)


class SecurityPipeline:
    """Run detectors sequentially, fail-fast on HIGH/CRITICAL."""

    BUILTIN_DETECTORS: ClassVar[dict[str, type[BaseDetector]]] = {
        "prompt_injection": PromptInjectionDetector,
        "canary": CanaryDetector,
        "anomaly": AnomalyDetector,
        "behavior": BehaviorDetector,
        "pii": PIIDetector,
    }

    @classmethod
    def register_detector(cls, name: str, detector_cls: type[BaseDetector]) -> None:
        cls.BUILTIN_DETECTORS[name] = detector_cls

    def __init__(self, detectors: Sequence[BaseDetector] | None = None, config: dict | None = None) -> None:
        self.detectors: list[BaseDetector] = list(detectors or [])
        self._config = config or {}

    @classmethod
    def from_config(cls, config: dict, extra_detectors: Sequence[BaseDetector] | None = None) -> SecurityPipeline:
        """Build a pipeline from a config dict (see open-sorcerer/config.yaml)."""
        detectors: list[BaseDetector] = []
        cmap = dict(cls.BUILTIN_DETECTORS)
        dc = config.get("detectors", {})

        for name, opts in dc.items():
            if not isinstance(opts, dict):
                opts = {"enabled": bool(opts)}
            if not opts.get("enabled", True):
                continue
            params = dict(opts.get("params", {}))
            if name == "canary":
                # CanaryDetector wants a Canary instance OR token_length.
                tl = params.pop("token_length", 32)
                detectors.append(CanaryDetector(token_length=tl))
            elif name in cmap:
                detectors.append(cmap[name](**params))
            # unknown named detectors are ignored (fall through to extra)

        if extra_detectors:
            detectors.extend(extra_detectors)

        return cls(detectors, config)

    def add(self, detector: BaseDetector) -> None:
        self.detectors.append(detector)

    def scan(
        self,
        text: str,
        session: str | None = None,
        fail_fast: bool | None = None,
    ) -> ScanResult:
        """Scan; fail-fast stops the chain at the first HIGH/CRITICAL."""
        config = getattr(self, "_config", {})
        if fail_fast is None:
            fail_fast = config.get("pipeline", {}).get("fail_fast", True)

        results: list[DetectorResult] = []
        for det in self.detectors:
            if getattr(det, "session_aware", False):
                r = det.scan(text, session=session)
            else:
                r = det.scan(text)
            results.append(r)
            if fail_fast and r.severity >= Severity.HIGH:
                break

        # Escalate on conclusive evidence (HIGH+, weak-signal, encoded
        # sub-threshold static) so repeated evasion ratchets up.
        if any(
            r.severity >= Severity.HIGH
            or any(f == "anomaly_plus_weak_signal" for f in r.findings)
            or (r.detector == "prompt_injection" and r.flagged and r.obfuscated
                and r.severity == Severity.MEDIUM)
            for r in results
        ):
            max_sev = max((r.severity for r in results), default=Severity.INFO)
            for det in self.detectors:
                if hasattr(det, "note_flagged"):
                    det.note_flagged(session, severity=max_sev)

        blocked = any(r.severity >= Severity.HIGH for r in results)

        # Audit record for every decision, blocked or not.
        log = self._audit_record(text, results, blocked)
        _AUDIT.log(
            logging.ERROR if blocked else logging.WARNING if results and any(r.flagged for r in results) else logging.INFO,
            msg="scan",
            extra={"open-sorcerer": log},
        )
        return ScanResult(text=text, results=results, blocked=blocked, log=log)

    @staticmethod
    def _audit_record(text: str, results: list[DetectorResult], blocked: bool) -> dict:
        """JSON-serialisable audit record for one scan."""
        findings = [
            {
                "detector": r.detector,
                "flagged": r.flagged,
                "severity": r.severity.name,
                "risk": r.score,
                "confidence": r.confidence,
                "findings": r.findings,
                "obfuscated": r.obfuscated,
            }
            for r in results
            if r.flagged
        ]
        return {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "blocked": blocked,
            "max_severity": max((r.severity for r in results), default=Severity.INFO).name,
            "findings": findings,
        }

    def check(self, text: str, session: str | None = None) -> bool:
        """True if the pipeline blocks the text (any HIGH/CRITICAL)."""
        return self.scan(text, session=session).blocked
