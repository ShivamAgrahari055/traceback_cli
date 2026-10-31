"""Tests for the secret redactor."""

import sys

import pytest

sys.path.insert(0, "c:/traceback-cli/src")

from tb_core.security.redactor import SecretRedactor


def test_redact_api_key():
    """API keys should be redacted."""
    redactor = SecretRedactor()
    result = redactor.redact("api_key=sk-1234567890abcdef")
    assert "[REDACTED]" in result
    assert "sk-1234567890abcdef" not in result


def test_redact_jwt():
    """JWT tokens should be redacted."""
    redactor = SecretRedactor()
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    result = redactor.redact(f"Authorization: Bearer {token}")
    assert "[REDACTED]" in result
    assert token not in result


def test_redact_password():
    """Passwords should be redacted."""
    redactor = SecretRedactor()
    result = redactor.redact("password=mysecret123")
    assert "[REDACTED]" in result
    assert "mysecret123" not in result


def test_redact_email():
    """Email addresses should be redacted."""
    redactor = SecretRedactor()
    result = redactor.redact("Contact admin@example.com for help")
    assert "[REDACTED]" in result
    assert "admin@example.com" not in result


def test_redact_preserves_surrounding_text():
    """Non-secret surrounding text should be preserved."""
    redactor = SecretRedactor()
    result = redactor.redact("User login failed with api_key=secret123 at 10:30")
    assert "User login failed" in result
    assert "at 10:30" in result
    assert "secret123" not in result


def test_redact_none():
    """None input should return None."""
    redactor = SecretRedactor()
    assert redactor.redact(None) is None


def test_redact_empty():
    """Empty string should return empty string."""
    redactor = SecretRedactor()
    assert redactor.redact("") == ""
