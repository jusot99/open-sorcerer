"""PIIDetector: known shapes flag at the right severity, lookalikes pass."""

from __future__ import annotations

from open_sorcerer.detectors import PIIDetector
from open_sorcerer.detectors.base import Severity


def test_email_flags_medium_only():
    res = PIIDetector().scan("Contact jane.doe@example.com for details.")
    assert res.flagged
    assert res.severity == Severity.MEDIUM
    assert res.findings == ["email"]


def test_phone_intl_and_nanp_flag_medium():
    for text in ("Call me at +1-415-555-0132 tomorrow.", "My number is (415) 555-0132."):
        res = PIIDetector().scan(text)
        assert res.flagged, text
        assert res.severity == Severity.MEDIUM, text
        assert res.findings == ["phone"], text


def test_ssn_with_context_blocks():
    res = PIIDetector().scan("My SSN is 123-45-6789.")
    assert res.flagged
    assert res.severity == Severity.HIGH
    assert res.findings == ["ssn"]


def test_ssn_without_context_flags_only():
    res = PIIDetector().scan("Reference 123-45-6789 closed.")
    assert res.flagged
    assert res.severity == Severity.MEDIUM
    assert res.findings == ["possible_ssn"]


def test_card_passing_luhn_blocks():
    res = PIIDetector().scan("Charge 4111111111111111 now.")
    assert res.flagged
    assert res.severity == Severity.HIGH
    assert res.findings == ["credit_card"]


def test_card_failing_luhn_passes():
    res = PIIDetector().scan("Order 4111111111111112 confirmed.")
    assert not res.flagged


def test_long_digit_run_with_valid_window_passes():
    # 22 digits containing a Luhn valid stretch: the lookaround boundaries
    # refuse to align inside the run, so no card finding.
    res = PIIDetector().scan("Order 99994111111111111111 confirmed.")
    assert "credit_card" not in res.findings


def test_leading_digit_run_with_valid_window_passes():
    # Same boundary rule at the start of the run.
    res = PIIDetector().scan("99994111111111111111 is my order")
    assert "credit_card" not in res.findings


def test_card_all_same_digits_passes():
    res = PIIDetector().scan("Code 0000000000000000 here.")
    assert not res.flagged


def test_known_secret_shapes_block():
    cases = {
        "Key AKIAIOSFODNN7EXAMPLE leaked.": "aws_access_key",
        "Token ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa here.": "github_token",
        "Key sk-abcdefghijklmnopqrst here.": "api_key",
    }
    for text, finding in cases.items():
        res = PIIDetector().scan(text)
        assert res.flagged, text
        assert res.severity == Severity.HIGH, text
        assert res.findings == [finding], text


def test_private_key_block_is_critical():
    res = PIIDetector().scan("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
    assert res.flagged
    assert res.severity == Severity.CRITICAL
    assert res.findings == ["private_key"]


def test_lookalikes_pass():
    for text in (
        "My order number is 1234567890.",
        "The test key sk-test-123 is expired.",
        "Short key sk-abcdefghijklmnopqr does nothing.",
        "Ping bob@localhost after lunch.",
        "Version 2.4.1 is out.",
        "",
    ):
        assert not PIIDetector().scan(text).flagged, text


def test_key_ending_in_underscore_flags():
    res = PIIDetector().scan("Key sk-abcdefghijklmnopqrst_ rotated.")
    assert res.flagged
    assert res.severity == Severity.HIGH
    assert res.findings == ["api_key"]


def test_threshold_gates_flagging():
    res = PIIDetector(threshold=100.0).scan("Charge 4111111111111111 now.")
    assert not res.flagged


def test_findings_never_carry_values():
    res = PIIDetector().scan("Charge 4111111111111111 now.")
    assert "4111111111111111" not in str(res.findings)
