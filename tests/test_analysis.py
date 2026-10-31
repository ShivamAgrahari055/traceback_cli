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


def _make_event(event_id, timestamp, level, message, exception_type=None, service=None):
    return Event(
        event_id=event_id,
        timestamp=timestamp,
        level=level,
        message=message,
        exception_type=exception_type,
        service=service,
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
    assert result == []
