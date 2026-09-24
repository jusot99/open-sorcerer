from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass
class DetectionResult:
    blocked: bool
    score: float = 0.0
    attack_type: str | None = None
    reason: str | None = None


class Detector(Protocol):
    def scan(self, text: str) -> DetectionResult:
        ...
