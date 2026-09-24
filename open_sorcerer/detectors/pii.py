"""PII and secret detector: emails, phones, SSNs, cards, known secret shapes.

Known shapes only. No entropy fallback: on a blocking detector, entropy
flagging drops legitimate traffic (hashes, UUIDs, session IDs).
"""

from __future__ import annotations

import re

from .base import BaseDetector, DetectorResult, Severity

# Finding -> (risk, severity). HIGH and above blocks in the pipeline,
# MEDIUM only flags. Findings carry category names only, never the matched
# values, so secrets cannot leak into the audit log.
_FINDING_RISK: dict[str, tuple[float, Severity]] = {
    "private_key": (80.0, Severity.CRITICAL),
    "credit_card": (60.0, Severity.HIGH),
    "ssn": (60.0, Severity.HIGH),
    "aws_access_key": (60.0, Severity.HIGH),
    "github_token": (60.0, Severity.HIGH),
    "api_key": (60.0, Severity.HIGH),
    "possible_ssn": (30.0, Severity.MEDIUM),
    "email": (30.0, Severity.MEDIUM),
    "phone": (30.0, Severity.MEDIUM),
}

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_INTL_RE = re.compile(r"\+\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}")
_PHONE_NANP_RE = re.compile(r"\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
# Only "ssn" or "social security" promote to HIGH. Bare "social" is prose,
# so "my social is ..." stays MEDIUM.
_SSN_CONTEXT_RE = re.compile(r"ssn|social[\s-]?security", re.IGNORECASE)
# Boundaries are lookarounds, not \b: a card run must start and end away
# from other digits, so a Luhn valid window inside a longer run can never align.
_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_AWS_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GITHUB_RE = re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")
# 20+ chars keeps prose and truncated keys out. Underscore breaks the run,
# so Stripe style sk_live_ keys never match by construction; the trailing
# lookahead (instead of \b) still matches keys ending in underscore.
_API_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9]{20,}(?![A-Za-z0-9])")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


class PIIDetector(BaseDetector):
    """Flag personal data and secrets by shape. Luhn gates cards, context
    gates SSNs; everything else is a labeled prefix or fixed format."""

    name = "pii"

    def __init__(self, threshold: float = 0.0) -> None:
        self._threshold = threshold

    def scan(self, text: str, **kwargs: object) -> DetectorResult:
        if text is None:
            text = ""
        findings = self._find(text)
        if not findings:
            return DetectorResult(
                detector=self.name,
                flagged=False,
                severity=Severity.INFO,
                findings=[],
            )
        risk, severity = max((_FINDING_RISK[f] for f in findings), key=lambda item: item[0])
        validated = any(_FINDING_RISK[f][1] >= Severity.HIGH for f in findings)
        return DetectorResult(
            detector=self.name,
            flagged=risk >= self._threshold and len(findings) > 0,
            severity=severity,
            score=round(risk, 1),
            confidence=0.95 if validated else 0.85,
            findings=sorted(set(findings)),
        )

    def _find(self, text: str) -> list[str]:
        out: list[str] = []
        if _PRIVATE_KEY_RE.search(text):
            out.append("private_key")
        for match in _CARD_RE.finditer(text):
            digits = re.sub(r"[ -]", "", match.group(0))
            if (
                digits.isdigit()
                and 13 <= len(digits) <= 19
                and len(set(digits)) > 1
                and _luhn_ok(digits)
            ):
                out.append("credit_card")
                break
        for match in _SSN_RE.finditer(text):
            window = text[max(0, match.start() - 40):match.end() + 40]
            out.append("ssn" if _SSN_CONTEXT_RE.search(window) else "possible_ssn")
        if _AWS_RE.search(text):
            out.append("aws_access_key")
        if _GITHUB_RE.search(text):
            out.append("github_token")
        if _API_KEY_RE.search(text):
            out.append("api_key")
        if _EMAIL_RE.search(text):
            out.append("email")
        if _PHONE_INTL_RE.search(text) or _PHONE_NANP_RE.search(text):
            out.append("phone")
        return out
