"""Tests for the report generators (Markdown and JSON)."""

import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, "c:/traceback-cli/src")

from tb_core.reporting.markdown import MarkdownReporter
from tb_core.reporting.json_report import JSONReporter
from tb_core.core.models import Incident, Event, Evidence

UTC = timezone.utc
T1 = datetime(2023, 10, 27, 10, 30, 1, tzinfo=UTC)
T2 = datetime(2023, 10, 27, 10, 30, 2, tzinfo=UTC)


def _make_incident():
    event = Event(
        event_id="e1",
        timestamp=T1,
        level="ERROR",
        message="Database connection failed",
        service="db",
        request_id="REQ-1",
    )
    return Incident(
        incident_id="TB-001",
        title="Database timeout",
        severity="CRITICAL",
        start_time=T1,
        end_time=T2,
        primary_error="Database connection failed",
        related_events=[event],
        request_id="REQ-1",
        affected_services=["db"],
        suspected_failure_points=["database"],
        possible_root_causes=["connection timeout"],
        recommendations=["Check database connectivity"],
        confidence="HIGH",
        evidence=[
            Evidence(
                finding="Database connection timed out",
                event_ids=["e1"],
                source_file="db.log",
                line_number=10,
                confidence="HIGH",
                is_observed=True,
            )
        ],
        analysis_metadata={},
    )


def test_markdown_report_generation():
    """Markdown report should contain key incident fields."""
    reporter = MarkdownReporter()
    inc = _make_incident()
    report = {
        "incident": inc,
        "title": inc.title,
        "severity": inc.severity,
        "summary": "Test summary",
        "root_cause": {
            "title": "Root cause",
            "confidence": "HIGH",
            "summary": "Root cause summary",
            "primary_error": inc.primary_error,
            "suspicious_event": inc.related_events[0],
        },
        "cascade_chain": [],
        "recommendations": ["Check database connectivity"],
        "evidence": inc.evidence,
        "events": inc.related_events,
        "start_time": inc.start_time,
        "end_time": inc.end_time,
        "primary_error": inc.primary_error,
        "affected_services": inc.affected_services,
        "confidence": inc.confidence,
    }
    output = reporter.generate(report)
    assert "TB-001" in output
    assert "CRITICAL" in output
    assert "Database connection failed" in output
    assert "Database timeout" in output


def test_json_report_generation():
    """JSON report should contain the complete structured incident."""
    reporter = JSONReporter()
    inc = _make_incident()
    report = {
        "incident": inc,
        "title": inc.title,
        "severity": inc.severity,
        "summary": "Test summary",
        "confidence": inc.confidence,
        "start_time": inc.start_time,
        "end_time": inc.end_time,
        "primary_error": inc.primary_error,
        "affected_services": inc.affected_services,
        "cascade_chain": [],
        "recommendations": [],
        "evidence": [],
        "events": inc.related_events,
        "analysis_metadata": {"generated_at": "2023-10-27T10:30:00Z"},
    }
    output = reporter.generate_report(report)
    assert "TB-001" in output
    assert "CRITICAL" in output
    assert "Database connection failed" in output
