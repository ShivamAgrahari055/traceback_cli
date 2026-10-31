"""Tests for the timeline reconstruction engine."""

import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, "c:/traceback-cli/src")

from tb_core.core.timeline import Timeline
from tb_core.core.models import Event

UTC = timezone.utc
T1 = datetime(2023, 10, 27, 10, 30, 1, tzinfo=UTC)
T2 = datetime(2023, 10, 27, 10, 30, 2, tzinfo=UTC)
T3 = datetime(2023, 10, 27, 10, 30, 3, tzinfo=UTC)


def _make_event(event_id, timestamp, level, message, exception_type=None):
    return Event(
        event_id=event_id,
        timestamp=timestamp,
        level=level,
        message=message,
        exception_type=exception_type,
    )


def test_timeline_builds_chronological_order():
    """Timeline should sort events chronologically."""
    events = [
        _make_event("e3", T3, "ERROR", "Last error"),
        _make_event("e1", T1, "INFO", "First event"),
        _make_event("e2", T2, "WARNING", "Middle event"),
    ]
    result = Timeline().build(events)
    ids = [item["event"].event_id for item in result["events"]]
    assert ids == ["e1", "e2", "e3"]


def test_timeline_flags_first_exception():
    """The first ERROR/CRITICAL event should be flagged as first exception."""
    events = [
        _make_event("e1", T1, "INFO", "Start"),
        _make_event("e2", T2, "ERROR", "First error", exception_type="TypeError"),
        _make_event("e3", T3, "CRITICAL", "Critical error", exception_type="RuntimeError"),
    ]
    result = Timeline().build(events)
    assert result["first_exception"] == "e2"


def test_timeline_flags_critical():
    """CRITICAL events should be flagged as critical failure."""
    events = [
        _make_event("e1", T1, "INFO", "Start"),
        _make_event("e2", T2, "CRITICAL", "Critical failure"),
    ]
    result = Timeline().build(events)
    assert "e2" in result["critical_ids"]


def test_timeline_empty():
    """Empty input should return empty timeline."""
    result = Timeline().build([])
    assert result["events"] == []
    assert result["first_exception"] is None


def test_timeline_detects_out_of_order():
    """Out-of-order timestamps should be detected as anomalies."""
    events = [
        _make_event("e2", T2, "ERROR", "Later"),
        _make_event("e1", T1, "INFO", "Earlier"),
    ]
    result = Timeline().build(events)
    # After sorting, no anomaly should exist
    assert result["anomalies"] == []
