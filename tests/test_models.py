"""Tests for core data models: Event, Incident, IncidentGroup."""

import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, "c:/traceback-cli/src")

from tb_core.core.models import Event, Incident, IncidentGroup

# UTC now for deterministic tests
UTC = timezone.utc
T1 = datetime(2023, 10, 27, 10, 30, 1, tzinfo=UTC)
T2 = datetime(2023, 10, 27, 10, 30, 6, tzinfo=UTC)


def test_event_construction():
    """Event can be constructed with all fields."""
    event = Event(
        event_id="abcd1234",
        timestamp=T1,
        level="INFO",
        message="Test message",
        service="api",
        request_id="req-1",
        trace_id="trace-1",
        session_id="sess-1",
        source_file="app.log",
        line_number=10,
        exception_type="TypeError",
        stack_trace="File \"app.py\", line 10",
        metadata={"key": "value"},
        raw_line="2023-10-27 10:30:01 INFO Test",
    )

    assert event.event_id == "abcd1234"
    assert event.level == "INFO"
    assert event.message == "Test message"
    assert event.service == "api"
    assert event.request_id == "req-1"
    assert event.metadata == {"key": "value"}


def test_event_level_normalization():
    """Event level should be uppercased."""
    event = Event(
        event_id="x", timestamp=T1, level="warning", message="Test"
    )
    assert event.level == "WARNING"


def test_event_required_fields():
    """Event requires event_id, timestamp, and message."""
    with pytest.raises(ValueError):
        Event(timestamp=T1, level="INFO", message="no id")


def test_event_timezone_naive_not_forced():
    """Event accepts naive timestamps (normalizer should handle timezone)."""
    from datetime import datetime

    naive = datetime(2023, 10, 27, 10, 30, 1)
    event = Event(
        event_id="x", timestamp=naive, level="INFO", message="Test"
    )
    assert event.timestamp == naive


def test_incident_construction():
    """Incident can be constructed with all fields."""
    event = Event(
        event_id="e1", timestamp=T1, level="ERROR", message="Fail"
    )
    incident = Incident(
        incident_id="TB-001",
        title="Database timeout",
        severity="CRITICAL",
        start_time=T1,
        end_time=T2,
        primary_error="Connection timeout",
        related_events=[event],
        request_id="req-1",
        trace_id="trace-1",
        affected_services=["api", "db"],
        suspected_failure_points=["db"],
        possible_root_causes=["db connection timeout"],
        recommendations=["Retry with backoff"],
        confidence="HIGH",
        evidence=[],
        analysis_metadata={},
    )

    assert incident.severity == "CRITICAL"
    assert incident.affected_services == ["api", "db"]


def test_incidentgroup_best_severity():
    """IncidentGroup.best_severity returns the highest severity in the group."""
    group = IncidentGroup(title="Test group")
    assert group.best_severity() == "INFO"

    from tb_core.core.models import Event

    group_with_error = IncidentGroup(
        title="Test group",
        events=[
            Event(event_id="1", timestamp=T1, level="INFO", message="Start"),
            Event(event_id="2", timestamp=T2, level="ERROR", message="Fail"),
        ],
    )
    assert group_with_error.best_severity() == "ERROR"

    group_with_critical = IncidentGroup(
        title="Test group",
        events=[
            Event(event_id="1", timestamp=T1, level="INFO", message="Start"),
            Event(event_id="2", timestamp=T2, level="CRITICAL", message="Fatal"),
        ],
    )
    assert group_with_critical.best_severity() == "CRITICAL"


def test_incidentgroup_affected_services():
    """IncidentGroup.affected_services returns sorted unique services."""
    group = IncidentGroup(
        title="Test",
        events=[
            Event(event_id="1", timestamp=T1, level="INFO", message="Start", service="api"),
            Event(event_id="2", timestamp=T2, level="ERROR", message="Fail", service="db"),
            Event(event_id="3", timestamp=T2, level="ERROR", message="Another", service="api"),
        ],
    )
    assert group.affected_services == ["api", "db"]


def test_incidentgroup_time_range():
    """IncidentGroup start_time/end_time reflect the event range."""
    group = IncidentGroup(
        title="Test",
        events=[
            Event(event_id="1", timestamp=T1, level="INFO", message="Start"),
            Event(event_id="2", timestamp=T2, level="ERROR", message="Fail"),
        ],
    )
    assert group.start_time == T1
    assert group.end_time == T2


def test_incidentgroup_empty_time_range():
    """Empty group has None start/end time."""
    group = IncidentGroup(title="Empty")
    assert group.start_time is None
    assert group.end_time is None
