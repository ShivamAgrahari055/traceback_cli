"""Tests for the analysis engine (rules, root cause, cascade)."""

import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, "c:/traceback-cli/src")

from tb_core.analysis.rules import RulesEngine, PATTERNS
from tb_core.analysis.root_cause import RootCauseAnalyzer
from tb_core.analysis.cascade import CascadeAnalyzer
from tb_core.core.models import Event, IncidentGroup as CoreIncidentGroup

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


def test_rules_detect_null_reference():
    """Null reference pattern should be detected."""
    rules = RulesEngine()
    pat = rules.detect("Cannot read properties of null", "TypeError")
    assert pat == "null_reference"


def test_rules_detect_database_timeout():
    """Database timeout pattern should be detected."""
    rules = RulesEngine()
    pat = rules.detect("Connection timeout", None)
    assert pat == "database_connection_timeout"


def test_rules_no_match():
    """Non-matching messages should return None."""
    rules = RulesEngine()
    pat = rules.detect("Everything is fine", None)
    assert pat is None


def test_root_cause_analyzer_empty():
    """Empty group should return a valid (empty) analysis."""
    group = CoreIncidentGroup(title="Empty", events=[])
    analyzer = RootCauseAnalyzer()
    result = analyzer.analyze(group)
    assert result["title"] == "No events"
    assert result["confidence"] == "LOW"


def test_root_cause_identifies_primary_error():
    """Primary error should be the first ERROR message."""
    events = [
        _make_event("e1", T1, "INFO", "Start"),
        _make_event("e2", T2, "ERROR", "Database connection failed"),
    ]
    group = CoreIncidentGroup(title="Test", events=events)
    analyzer = RootCauseAnalyzer()
    result = analyzer.analyze(group)
    assert result["primary_error"] == "Database connection failed"


def test_cascade_analyzer_empty():
    """Empty group should return empty cascade."""
    group = CoreIncidentGroup(title="Empty", events=[])
    cascade = CascadeAnalyzer()
    result = cascade.analyze(group)
    assert result["root_cause"] is None
    assert result["downstream_failures"] == []


def test_cascade_analyzer_returns_dict_format():
    """Cascade analyzer should return dict with root_cause and downstream_failures."""
    events = [
        _make_event("e1", T1, "ERROR", "Database timeout", service="db"),
        _make_event("e2", T2, "ERROR", "Query failed", service="db", request_id="REQ-1"),
    ]
    group = CoreIncidentGroup(title="Test", events=events)
    cascade = CascadeAnalyzer()
    result = cascade.analyze(group)
    assert "root_cause" in result
    assert "downstream_failures" in result
    assert result["root_cause"].event_id == "e1"
    assert len(result["downstream_failures"]) >= 0


def test_cascade_excludes_normal_events():
    """Cascade should not include INFO/WARNING events as downstream failures."""
    events = [
        _make_event("e1", T1, "INFO", "Waiting for response", service="api"),
        _make_event("e2", T2, "ERROR", "Database timeout", service="db"),
        _make_event("e2b", T2, "INFO", "Normal operation", service="api"),
        _make_event("e3", T1, "ERROR", "API error", service="api", request_id="REQ-1"),
    ]
    group = CoreIncidentGroup(title="Test", events=events)
    cascade = CascadeAnalyzer()
    result = cascade.analyze(group)
    # Only ERROR/CRITICAL events should be in downstream
    for failure in result["downstream_failures"]:
        ev = failure.event_ids[0]
        level = next(e.level for e in events if e.event_id == ev)
        assert level in ("ERROR", "CRITICAL")


def test_root_cause_has_causal_categories():
    """Root cause analyzer should return all causal categories."""
    events = [
        _make_event("e1", T1, "INFO", "Query returned 0 rows", service="db", request_id="REQ-1"),
        _make_event("e2", T2, "ERROR", "Cannot read properties of null", "TypeError", "auth", "REQ-1"),
        _make_event("e3", T1, "ERROR", "HTTP 500 returned to client", service="api", request_id="REQ-1"),
    ]
    group = CoreIncidentGroup(title="Test", events=events)
    analyzer = RootCauseAnalyzer()
    result = analyzer.analyze(group)
    assert "root_cause_hypothesis" in result
    assert "supporting_evidence" in result
    assert "application_exception" in result
    assert "downstream_failures" in result
    assert "user_facing_impact" in result
    assert "confidence_explanation" in result


def test_root_cause_confidence_explanation():
    """Confidence should include an explanation string."""
    events = [
        _make_event("e1", T1, "INFO", "Query returned 0 rows", service="db", request_id="REQ-1"),
        _make_event("e2", T2, "ERROR", "Cannot read properties of null", "TypeError", "auth", "REQ-1"),
    ]
    group = CoreIncidentGroup(title="Test", events=events)
    analyzer = RootCauseAnalyzer()
    result = analyzer.analyze(group)
    assert "confidence_explanation" in result
    assert isinstance(result["confidence_explanation"], str)
    assert len(result["confidence_explanation"]) > 0


def test_root_cause_source_attribution():
    """Root cause should preserve service attribution."""
    events = [
        _make_event("e1", T1, "ERROR", "Cannot read properties of null", "TypeError", "auth", "REQ-1"),
    ]
    group = CoreIncidentGroup(title="Test", events=events)
    analyzer = RootCauseAnalyzer()
    result = analyzer.analyze(group)
    rch = result["root_cause_hypothesis"]
    assert rch is not None
    assert rch.service == "auth"


def test_root_cause_timestamp_precision_lowers_confidence():
    """Second-level timestamp precision should reduce confidence."""
    events = [
        _make_event("e1", T1, "INFO", "Query returned 0 rows", service="db", request_id="REQ-1"),
        _make_event("e2", T1, "ERROR", "Cannot read properties of null", "TypeError", "auth", "REQ-1"),
    ]
    group = CoreIncidentGroup(title="Test", events=events)
    analyzer = RootCauseAnalyzer()
    result = analyzer.analyze(group)
    # With correlation + service + multiple causes but timestamp precision penalty,
    # confidence should be MEDIUM or LOW, not HIGH
    assert result["confidence"] in ("LOW", "MEDIUM")


def test_root_cause_stack_trace_increases_confidence():
    """Stack trace on root cause should increase confidence."""
    events_no_trace = [
        _make_event("e1", T1, "INFO", "Query returned 0 rows", service="db", request_id="REQ-1"),
        _make_event("e2", T2, "ERROR", "Cannot read properties of null", "TypeError", "auth", "REQ-1"),
    ]
    events_with_trace = [
        _make_event("e1", T1, "INFO", "Query returned 0 rows", service="db", request_id="REQ-1"),
        Event(
            event_id="e2",
            timestamp=T2,
            level="ERROR",
            message="Cannot read properties of null",
            exception_type="TypeError",
            service="auth",
            request_id="REQ-1",
            stack_trace="Traceback (most recent call last): ...",
        ),
    ]

    group1 = CoreIncidentGroup(title="Test", events=events_no_trace)
    group2 = CoreIncidentGroup(title="Test", events=events_with_trace)
    analyzer = RootCauseAnalyzer()

    result1 = analyzer.analyze(group1)
    result2 = analyzer.analyze(group2)

    # With stack trace, confidence should be >= without
    score_map = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    assert score_map[result2["confidence"]] >= score_map[result1["confidence"]]


def test_markdown_report_includes_rca_categories():
    """Markdown report should include new RCA categories."""
    from tb_core.reporting.markdown import MarkdownReporter
    from tb_core.core.models import Incident, Evidence

    event = Event(
        event_id="e1",
        timestamp=T1,
        level="ERROR",
        message="NullReferenceException",
        service="auth",
        request_id="REQ-1",
    )
    inc = Incident(
        incident_id="TB-001",
        title="Null ref",
        severity="ERROR",
        primary_error="NullReferenceException",
        related_events=[event],
        affected_services=["auth"],
    )
    reporter = MarkdownReporter()
    report = {
        "incident": inc,
        "title": inc.title,
        "severity": inc.severity,
        "summary": "Test summary",
        "root_cause": {
            "title": "Root cause",
            "confidence": "LOW",
            "confidence_explanation": "Test explanation",
            "primary_error": "NullReferenceException",
            "root_cause_hypothesis": event,
            "supporting_evidence": [
                Evidence(
                    finding="Database returned null",
                    event_ids=["e2"],
                    source_file="db.log",
                    confidence="MEDIUM",
                    is_observed=True,
                )
            ],
            "application_exception": event,
            "downstream_failures": [
                Evidence(
                    finding="HTTP 500 returned",
                    event_ids=["e3"],
                    source_file="api.log",
                    confidence="MEDIUM",
                    is_observed=True,
                )
            ],
            "user_facing_impact": [
                Evidence(
                    finding="Frontend displayed error",
                    event_ids=["e4"],
                    source_file="frontend.log",
                    confidence="MEDIUM",
                    is_observed=True,
                )
            ],
        },
        "cascade_chain": [],
        "recommendations": ["Check null guards"],
        "evidence": [],
        "events": [event],
        "start_time": T1,
        "end_time": T2,
        "primary_error": "NullReferenceException",
        "affected_services": ["auth"],
        "confidence": "LOW",
    }
    output = reporter.generate(report)
    assert "Root Cause Hypothesis" in output
    assert "Supporting Evidence" in output
    assert "Downstream Failures" in output
    assert "User-Facing Impact" in output
    assert "Test explanation" in output
