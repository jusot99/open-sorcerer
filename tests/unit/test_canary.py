"""Unit tests for canary token generation/verification and the canary detector."""

from open_sorcerer.canary import CANARY_PREFIX, Canary, contains_canary, generate
from open_sorcerer.detectors import CanaryDetector


def test_generate_uniqueness_and_length():
    a = generate(32)
    b = generate(32)
    assert len(a) == len(CANARY_PREFIX) + 32
    assert a.startswith(CANARY_PREFIX)
    assert a != b


def test_canary_issue_check():
    c = Canary()
    tok = c.issue()
    assert c.check(tok)
    assert c.check(f"leaked {tok} here")


def test_canary_revoke():
    c = Canary()
    tok = c.issue()
    c.revoke(tok)
    assert not c.check(tok)


def test_contains_canary_plain():
    assert not contains_canary("hello world", set())


def test_canary_detector_flags_leak():
    det = CanaryDetector()
    tok = det.issue()
    res = det.scan(f"system prompt leaked: {tok}")
    assert res.flagged
    assert res.severity.name == "CRITICAL"


def test_canary_detector_clean():
    det = CanaryDetector()
    det.issue()
    assert not det.scan("no leak here").flagged
