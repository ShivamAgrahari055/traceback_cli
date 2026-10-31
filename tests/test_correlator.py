"""Tests for the correlation engine."""

import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, "c:/traceback-cli/src")

from tb_core.core.correlator import IncidentCorrelator
from tb_core.core.models import Event, Incident

UTC = timezone.utc
T1 = datetime(2023, 10, 27, 10, 30, 1, tzinfo=UTC)
T2 = datetime(2023, 10, 27, 10, 30, 2, tzinfo=UTC)
T3 = datetime(2023, 10, 27, 10, 30, 3, tzinfo=UTC)


def _make_event(event_id, timestamp, level, message, service=None, request_id=None, trace_id=None):
    return Event(
        event_id=event_id,
        timestamp=timestamp,
        level=level,
        message=message,
        service=service,
        request_id=request_id,
        trace_id=trace_id,
    )


def test_correlate_groups_by_request_id():
    """Events with the same request_id should be grouped together."""
    events = [
        _make_event("e1", T1, "INFO", "Request received", service="api", request_id="REQ-1"),
        _make_event("e2", T2, "ERROR", "DB timeout", service="db", request_id="REQ-1"),
        _make_event("e3", T1, "INFO", "Unrelated", service="web", request_id="REQ-2"),
    ]
    correlator = IncidentCorrelator()
    incidents = correlator.correlate(events)
    assert len(incidents) == 2
    req1 = [i for i in incidents if i.incident_id == "REQ-1"][0]
    assert len(req1.related_events) == 2


def test_correlate_groups_by_trace_id():
    """Events with the same trace_id but no request_id should be grouped."""
    events = [
        _make_event("e1", T1, "INFO", "Start", service="api", trace_id="TRC-1"),
        _make_event("e2", T2, "ERROR", "Fail", service="db", trace_id="TRC-1"),
    ]
    correlator = IncidentCorrelator()
    incidents = correlator.correlate(events)
    assert len(incidents) == 1
    assert len(incidents[0].related_events) == 2


def test_correlate_untracked_grouping():
    """Events without identifiers should be grouped as untracked."""
    events = [
        _make_event("e1", T1, "INFO", "No id 1", service="api"),
        _make_event("e2", T2, "ERROR", "No id 2", service="db"),
    ]
    correlator = IncidentCorrelator()
    incidents = correlator.correlate(events)
    assert len(incidents) == 1


def test_correlate_preserves_chronological_order():
    """Events within an incident should be sorted chronologically."""
    events = [
        _make_event("e3", T3, "ERROR", "Last", service="api", request_id="REQ-1"),
        _make_event("e1", T1, "INFO", "First", service="api", request_id="REQ-1"),
        _make_event("e2", T2, "WARNING", "Middle", service="api", request_id="REQ-1"),
    ]
    correlator = IncidentCorrelator()
    incidents = correlator.correlate(events)
    inc = incidents[0]
    ids = [e.event_id for e in inc.related_events]
    assert ids == ["e1", "e2", "e3"]


def test_correlate_empty_input():
    """Empty input should return no incidents."""
    correlator = IncidentCorrelator()
    incidents = correlator.correlate([])
    assert incidents == []
