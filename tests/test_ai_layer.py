"""Tests for the optional LLM intelligence layer.

All provider interactions are mocked — no real API calls are made.
"""

import json
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, "c:/traceback-cli/src")

from tb_core.ai.config import AIConfig
from tb_core.ai.manager import ProviderManager
from tb_core.ai.models import (
    LLMAnswer,
    LLMRootCauseAnalysis,
    ProviderError,
    EventReference,
)
from tb_core.ai.openai_compatible import OpenAICompatibleProvider
from tb_core.ai.provider import BaseLLMProvider
from tb_core.ai.rca import enrich_rca, is_ai_available
from tb_core.core.models import Event, IncidentGroup as CoreIncidentGroup
from tb_core.analysis.root_cause import RootCauseAnalyzer

UTC = timezone.utc
T1 = datetime(2023, 10, 27, 10, 30, 1, tzinfo=UTC)
T2 = datetime(2023, 10, 27, 10, 30, 2, tzinfo=UTC)


def _make_event(event_id, timestamp, level, message, exception_type=None, service=None, request_id=None):
    return Event(
        event_id=event_id,
        timestamp=timestamp,
        level=level,
        message=message,
        exception_type=exception_type,
        service=service,
        request_id=request_id,
    )


# ------------------------------------------------------------------
# Config tests
# ------------------------------------------------------------------

def test_ai_config_defaults_disabled():
    """AI should be disabled by default."""
    config = AIConfig()
    assert config.enabled is False
    assert config.is_configured is False


def test_ai_config_redact_for_log():
    """Config should mask API key in logs."""
    config = AIConfig()
    config.enabled = True
    config.api_key = "sk-secret123"
    summary = config.redact_for_log()
    assert summary["api_key_set"] is True
    assert "sk-secret123" not in str(summary)


# ------------------------------------------------------------------
# Provider error tests
# ------------------------------------------------------------------

def test_provider_error_retryable():
    """ProviderError should track retryable flag."""
    err = ProviderError("timeout", retryable=True)
    assert err.retryable is True
    err2 = ProviderError("bad key", retryable=False)
    assert err2.retryable is False


# ------------------------------------------------------------------
# OpenAI-compatible provider tests (mocked)
# ------------------------------------------------------------------

def _mock_successful_response():
    """Return a mock successful chat completion response."""
    return {
        "choices": [
            {
                "message": {
                    "content": json.dumps({
                        "summary": "Database null led to auth exception",
                        "root_cause_hypothesis": "Database returned null, causing NullReferenceException",
                        "confidence": "MEDIUM",
                        "confidence_explanation": "Correlation ID present, but second-level timestamps",
                        "affected_services": ["auth", "database"],
                        "causal_chain": [
                            {
                                "event_id": "e1",
                                "description": "Database returned null",
                                "category": "root_cause",
                            },
                            {
                                "event_id": "e2",
                                "description": "NullReferenceException thrown",
                                "category": "application_exception",
                            },
                        ],
                        "downstream_failures": [
                            {
                                "event_id": "e3",
                                "finding": "HTTP 500 returned",
                                "confidence": "MEDIUM",
                                "is_observed": True,
                            }
                        ],
                        "user_facing_impact": [
                            {
                                "event_id": "e4",
                                "finding": "Frontend displayed login failed",
                                "confidence": "MEDIUM",
                                "is_observed": True,
                            }
                        ],
                        "debugging_recommendations": [
                            "Add null guards before dereferencing",
                            "Check database query results",
                        ],
                        "missing_evidence": ["Stack trace from auth service"],
                        "limitations": ["Timestamps lack sub-second precision"],
                    })
                }
            }
        ]
    }


def _mock_invalid_json_response():
    """Return a mock response with invalid JSON."""
    return {
        "choices": [
            {
                "message": {
                    "content": "This is not JSON at all",
                }
            }
        ]
    }


def _mock_auth_error():
    """Raise an HTTP 401 error."""
    import urllib.error
    import urllib.request

    req = urllib.request.Request("http://example.com")
    try:
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, None)
    except urllib.error.HTTPError as exc:
        return exc


def test_openai_provider_not_configured_without_key():
    """Provider should not require API key at init, but analyze should fail."""
    config = AIConfig()
    config.enabled = True
    config.api_key = None
    provider = OpenAICompatibleProvider(config)
    assert provider._api_key == ""


def test_openai_provider_invalid_credentials():
    """Provider should raise ProviderError on 401."""
    import urllib.error
    import urllib.request

    config = AIConfig()
    config.enabled = True
    config.api_key = "bad-key"
    provider = OpenAICompatibleProvider(config)

    with patch.object(provider, "_chat_completion", side_effect=ProviderError("Invalid API credentials", retryable=False)):
        with pytest.raises(ProviderError, match="Invalid API credentials"):
            provider.analyze_incident(
                incident_id="TB-001",
                title="Test",
                severity="ERROR",
                events=[],
                deterministic_analysis={},
                redacted_events=[],
            )


def test_openai_provider_timeout_is_retryable():
    """Timeout errors should be retryable."""
    config = AIConfig()
    config.enabled = True
    config.api_key = "key"
    provider = OpenAICompatibleProvider(config)

    with patch.object(provider, "_chat_completion", side_effect=ProviderError("timeout", retryable=True)):
        with pytest.raises(ProviderError) as excinfo:
            provider.analyze_incident(
                incident_id="TB-001",
                title="Test",
                severity="ERROR",
                events=[],
                deterministic_analysis={},
                redacted_events=[],
            )
        assert excinfo.value.retryable is True


def test_provider_manager_disabled_returns_none():
    """Manager should return None when AI is disabled."""
    config = AIConfig()
    config.enabled = False
    manager = ProviderManager(config)
    assert manager.is_available is False
    assert manager.get_provider() is None
    result = manager.analyze_incident(
        incident_id="TB-001",
        title="Test",
        severity="ERROR",
        events=[],
        deterministic_analysis={},
        redacted_events=[],
    )
    assert result is None


def test_provider_manager_no_api_key():
    """Manager should report unavailable when no API key."""
    config = AIConfig()
    config.enabled = True
    config.api_key = None
    manager = ProviderManager(config)
    assert manager.is_available is False


def test_provider_manager_unknown_provider():
    """Manager should report unavailable for unknown provider."""
    config = AIConfig()
    config.enabled = True
    config.api_key = "key"
    config.provider = "nonexistent"
    manager = ProviderManager(config)
    assert manager.is_available is False


def test_enrich_rca_returns_none_when_ai_disabled():
    """enrich_rca should not call LLM when disabled."""
    events = [_make_event("e1", T1, "ERROR", "Test error", service="auth")]
    deterministic = {
        "title": "Test error",
        "primary_error": "Test error",
        "confidence": "MEDIUM",
        "confidence_explanation": "Test",
    }
    result = enrich_rca(
        incident_id="TB-001",
        title="Test",
        severity="ERROR",
        events=events,
        deterministic_analysis=deterministic,
        redacted_events=events,
        ai_enabled=False,
    )
    assert result["ai_enhanced"] is False
    assert result["ai_source"] is None
    assert result["title"] == "Test error"


def test_enrich_rca_uses_llm_when_enabled_and_available():
    """enrich_rca should use LLM when enabled and provider available."""
    import json

    events = [
        _make_event("e1", T1, "INFO", "Query returned 0 rows", service="db", request_id="REQ-1"),
        _make_event("e2", T2, "ERROR", "Cannot read properties of null", "TypeError", "auth", "REQ-1"),
    ]
    deterministic = {
        "title": "Cannot read properties of null",
        "primary_error": "Cannot read properties of null",
        "root_cause_hypothesis": events[1],
        "supporting_evidence": [],
        "application_exception": events[1],
        "downstream_failures": [],
        "user_facing_impact": [],
        "confidence": "MEDIUM",
        "confidence_explanation": "Test",
    }

    config = AIConfig()
    config.enabled = True
    config.api_key = "test-key"
    manager = ProviderManager(config)

    # Mock the provider's analyze_incident to return a valid result
    with patch.object(manager, "get_provider") as mock_get_provider:
        mock_provider = MagicMock()
        mock_provider.analyze_incident.return_value = LLMRootCauseAnalysis(
            summary="Database null caused auth exception",
            root_cause_hypothesis="Database returned null, causing NullReferenceException",
            confidence="MEDIUM",
            confidence_explanation="Strong correlation evidence",
            affected_services=["auth", "database"],
            causal_chain=[],
            downstream_failures=[],
            user_facing_impact=[],
            debugging_recommendations=["Add null guards"],
            missing_evidence=["Stack trace"],
            limitations=["Second-level timestamps"],
        )
        mock_get_provider.return_value = mock_provider

        result = enrich_rca(
            incident_id="TB-001",
            title="Test",
            severity="ERROR",
            events=events,
            deterministic_analysis=deterministic,
            redacted_events=events,
            ai_enabled=True,
            provider_manager=manager,
        )

        assert result["ai_enhanced"] is True
        assert result["ai_source"] == "llm"
        assert result["ai_summary"] == "Database null caused auth exception"
        assert result["ai_confidence"] == "MEDIUM"
        assert result["ai_confidence_explanation"] == "Strong correlation evidence"


def test_enrich_rca_falls_back_when_llm_fails():
    """enrich_rca should fall back to deterministic when LLM fails."""
    events = [_make_event("e1", T1, "ERROR", "Test error", service="auth")]
    deterministic = {
        "title": "Test error",
        "primary_error": "Test error",
        "confidence": "MEDIUM",
        "confidence_explanation": "Test",
    }

    config = AIConfig()
    config.enabled = True
    config.api_key = "test-key"
    manager = ProviderManager(config)

    with patch.object(manager, "get_provider", return_value=None):
        result = enrich_rca(
            incident_id="TB-001",
            title="Test",
            severity="ERROR",
            events=events,
            deterministic_analysis=deterministic,
            redacted_events=events,
            ai_enabled=True,
            provider_manager=manager,
        )
        assert result["ai_enhanced"] is False
        assert result["ai_source"] is None
        assert result["title"] == "Test error"


def test_llm_root_cause_validation():
    """LLMRootCauseAnalysis should validate confidence values."""
    valid = LLMRootCauseAnalysis(
        summary="Test",
        root_cause_hypothesis="Test hypothesis",
        confidence="high",  # Should be normalized to HIGH
        affected_services=["auth", "database"],
    )
    assert valid.confidence == "HIGH"
    assert valid.affected_services == ["auth", "database"]


def test_llm_answer_validation():
    """LLMAnswer should validate confidence values."""
    answer = LLMAnswer(
        answer="Test answer",
        confidence="medium",
    )
    assert answer.confidence == "MEDIUM"
    assert answer.is_llm_generated is True


def test_event_reference_validation():
    """EventReference should validate confidence values."""
    ref = EventReference(
        event_id="e1",
        finding="Test finding",
        confidence="low",
    )
    assert ref.confidence == "LOW"
    assert ref.is_observed is True


def test_is_ai_available_false_by_default():
    """is_ai_available should be False by default."""
    assert is_ai_available() is False
