"""Hybrid anomaly detector: feature-based scoring + weak-signal co-occurrence."""

from __future__ import annotations

import math
import re
import statistics
import unicodedata
from collections import Counter
from dataclasses import dataclass, field

from ..encoding_normalizer import normalize
from .base import BaseDetector, DetectorResult, Severity

_ZWS_RE = re.compile(r"[\u200b-\u200d\u2060\ufeff]")

_OBFUSCATION_CONTROLS_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")

_HOMOGLYPH = str.maketrans(
    {
        "і": "i",
        "ј": "j",
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "α": "a",
        "ε": "e",
        "ο": "o",
        "ρ": "p",
    }
)

_NON_LETTER_RE = re.compile(r"[^a-zA-Z\s]")


def _normalize_for_signal(text: str) -> str:
    """Peel encoding layers so weak-signal words surface in plaintext."""
    n = normalize(text).lower()
    return _NON_LETTER_RE.sub("", n.translate(_HOMOGLYPH))


@dataclass
class TextProfile:
    """Feature stats from a benign corpus; drives the z-score threshold."""

    means: dict[str, float] = field(default_factory=dict)
    stds: dict[str, float] = field(default_factory=dict)

    def z(self, feats: dict[str, float]) -> dict[str, float]:
        return {
            k: (feats[k] - self.means.get(k, 0.0)) / (self.stds.get(k, 1.0) + 1e-9)
            for k in feats
        }

    @staticmethod
    def _max_z(z: dict[str, float]) -> float:
        """Worst single feature; one strongly-divergent feature is the signal."""
        return max((abs(v) for v in z.values()), default=0.0)

    def calibrate_threshold(self, corpus: list[str], k_mad: float = 4.0) -> float:
        """Threshold = median + k*MAD of max-z over clean text.

        Clean max-z sits near the median; attacks blow past it.
        """
        scores = [self._max_z(self.z(_features(t))) for t in corpus]
        med = statistics.median(scores)
        mad = statistics.median([abs(s - med) for s in scores]) or 1e-6
        return med + k_mad * mad


_WEAK_SIGNAL_WORDS = frozenset(
    {
        # Attack-distinct only; dual-use verbs (follow, switch, disable)
        # live in semantic authority_override, not here.
        "ignore",
        "disregard",
        "forget",
        "reveal",
        "override",
        "jailbreak",
        "bypass",
        "circumvent",
        "ignoreallfilters",
        "nofilters",
        "norestrictions",
        "nolimits",
        "noboundaries",
        "norules",
        "unrestricted",
        "uncensored",
        "unfiltered",
    }
)


def _has_obfuscation_evidence(text: str) -> bool:
    """True only when the raw text carried real bidi/zero-width/re-folding
    obfuscation, never for plain attack-flavoured prose."""
    if _OBFUSCATION_CONTROLS_RE.search(text):
        return True
    return normalize(text) != text


def _weak_signal_match(normalized_text: str) -> re.Match | None:
    """Weak-signal words, exact (word-boundary) or substring.

    Substring catches ignoreall, i.g.n.o.r.e (post-strip), 1gnore (post-leet).
    """
    m = re.search(
        r"\b(?:" + "|".join(re.escape(w) for w in _WEAK_SIGNAL_WORDS) + r")\b",
        normalized_text,
        re.IGNORECASE,
    )
    if m:
        return m

    stripped = _NON_LETTER_RE.sub("", normalized_text.lower())
    for tok in stripped.split():
        for w in _WEAK_SIGNAL_WORDS:
            if w in tok and tok != w:
                return re.search(re.escape(w), tok)
    return None


def _weak_signal_score(match: re.Match | None) -> float:
    """Deterministic MEDIUM-range score for a sub-threshold weak hit."""
    if match is None:
        return 30.0
    boost = 8.0 if match.group(0).lower() in ("reveal", "jailbreak") else 0.0
    return round(30.0 + boost + min(len(match.group(0)) - 3, 5), 1)


class AnomalyDetector(BaseDetector):
    """Feature-based anomaly scoring with hybrid static co-occurrence."""

    name: str = "anomaly"

    def __init__(
        self,
        profile: TextProfile | None = None,
        z_threshold: float | None = None,
        require_weak_static: bool = True,
    ) -> None:
        self._profile = profile if profile else _BUILTIN_PROFILE
        self._z_threshold = (
            z_threshold
            if z_threshold is not None
            else self._profile.calibrate_threshold(_SEED_TEXTS)
        )
        self._require_weak_static = require_weak_static

    def scan(self, text: str, **kwargs: object) -> DetectorResult:
        if not text:
            return DetectorResult(detector=self.name, flagged=False)

        feats = _features(text)
        z = self._profile.z(feats)
        combo = self._profile._max_z(z)

        evidence = _weak_signal_match(_normalize_for_signal(text))
        weak = evidence is not None
        obfuscated = _has_obfuscation_evidence(text)

        if combo < self._z_threshold:
            if weak:
                return DetectorResult(
                    detector=self.name,
                    flagged=True,
                    severity=Severity.MEDIUM,
                    score=_weak_signal_score(evidence),
                    confidence=0.7,
                    findings=["weak_signal_below_threshold"],
                    obfuscated=obfuscated,
                )
            return DetectorResult(detector=self.name, flagged=False)

        top_features = sorted(z.items(), key=lambda kv: abs(kv[1]), reverse=True)[:3]
        top_tags = [f for f, _ in top_features]

        if self._require_weak_static and not weak:
            return DetectorResult(
                detector=self.name,
                flagged=True,
                severity=Severity.MEDIUM,
                score=min(100.0, round(combo * 10, 1)),
                confidence=min(0.95, 0.5 + combo / 20),
                findings=["anomaly_no_static_signal"] + top_tags,
                obfuscated=obfuscated,
            )

        return DetectorResult(
            detector=self.name,
            flagged=True,
            severity=Severity.HIGH,
            score=min(100.0, round(combo * 10, 1)),
            confidence=min(0.95, 0.5 + combo / 20),
            findings=["anomaly_plus_weak_signal"] + top_tags,
            obfuscated=obfuscated,
        )


def _features(text: str) -> dict[str, float]:
    enc = _ZWS_RE.sub("", text)
    if not enc:
        return {
            "entropy": 0.0,
            "char_class_entropy": 0.0,
            "digit_ratio": 0.0,
            "repeat_ratio": 0.0,
            "uppercase_ratio": 0.0,
            "alpha_ratio": 0.0,
        }

    code = [ord(c) for c in enc]
    entropy = _shannon(code)
    char_class_entropy = _shannon([_cls(c) for c in enc])
    digit_ratio = sum(c.isdigit() for c in enc) / len(enc)
    repeat_ratio = _repeat_ratio(enc)
    uppercase_ratio = sum(c.isupper() for c in enc) / len(enc)
    alpha_ratio = sum(c.isalpha() for c in enc) / len(enc)
    return {
        "entropy": entropy,
        "char_class_entropy": char_class_entropy,
        "digit_ratio": digit_ratio,
        "repeat_ratio": repeat_ratio,
        "uppercase_ratio": uppercase_ratio,
        "alpha_ratio": alpha_ratio,
    }


def _shannon(values: list[int]) -> float:
    counts = Counter(values)
    total = float(len(values))
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


_CATEGORY = {"L": 1, "M": 2, "N": 3, "P": 4, "S": 5, "Z": 6, "C": 7}


def _cls(ch: str) -> int:
    if ch.isascii():
        return 11 if ch.isalnum() else 12
    return _CATEGORY.get(unicodedata.category(ch)[0], 0)


def _repeat_ratio(text: str) -> float:
    if len(text) < 2:
        return 0.0
    repeats = sum(1 for i in range(1, len(text)) if text[i] == text[i - 1])
    return repeats / (len(text) - 1)


def fit_profile(texts: list[str] | None = None) -> TextProfile:
    samples = texts if texts else _SEED_TEXTS
    rows = [_features(t) for t in samples]
    keys = rows[0].keys()
    means = {k: sum(r[k] for r in rows) / len(rows) for k in keys}
    stds = {
        k: math.sqrt(sum((r[k] - means[k]) ** 2 for r in rows) / max(len(rows) - 1, 1)) or 1e-6
        for k in keys
    }
    return TextProfile(means=means, stds=stds)


_SEED_TEXTS = [
    "Please summarize the attached document in three bullet points.",
    "Translate this sentence to Portuguese and return the result.",
    "What is the capital of France? Answer briefly.",
    "Can you help me write a Python function that parses CSV files?",
    "Summarize the key arguments from both sides of the debate.",
    "Rewrite the following paragraph in a more formal tone.",
    "Explain the difference between TCP and UDP protocols.",
    "What are the best practices for securing a REST API?",
    "Write a concise email requesting a meeting with the project lead.",
    "Compare the time complexity of quicksort and mergesort.",
    "Could you draft a short blog post about the latest trends in technology.",
    "Please proofread this essay and point out any spelling mistakes.",
    "Help me brainstorm some names for my new coffee shop.",
    "Explain how a blockchain works in simple terms for a beginner.",
    "Summarize the plot of the movie in just two sentences.",
    "What is the boiling point of water at sea level?",
    "Write a short goodbye email to a coworker who left the company.",
    "Compare the nutritional value of an apple and a banana.",
    "Give me a step by step guide to changing a car tire.",
    "What are the most common symptoms of the common cold?",
    "Translate the word sunshine into Spanish, German and French.",
    "How do I reset my home router back to factory settings?",
    "Suggest a weekly workout plan for someone who is new to the gym.",
    "What is the difference between a meteor and a comet?",
    "Summarize these meeting notes into a list of action items.",
    "Write a polite refusal to a friend who asked to borrow money.",
    "Explain the water cycle to a ten year old child.",
    "What are the health benefits of drinking green tea every day?",
    "Draft a short welcome message for a new team member.",
    "Suggest a quick itinerary for a three day trip to Paris.",
    # Benign traffic carries digits (order numbers, versions, dates, prices,
    # phone numbers). The seeds above have almost none, so any digit count
    # scored as extreme. These keep digit_ratio calibrated to ordinary text.
    "My order number is 1234567890, please check the shipping status.",
    "Version 2.4.1 is out, see the changelog for details.",
    "Call me back at 415-555-0132 after 5pm.",
    "The meeting is on 2026-09-20 at 3pm in room 404.",
    "Your total is $42.50 for 3 items.",
    "Flight BA2490 departs at 18:45 from gate B12.",
    "My zip code is 90210 and the package weighs 2kg.",
    "Python 3.12 was released in October 2023.",
    "The invoice INV-2024-8841 is due in 30 days.",
    "The error code is 0x80070005, try rebooting first.",
]

_BUILTIN_PROFILE = fit_profile(_SEED_TEXTS)
