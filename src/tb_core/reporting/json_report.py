"""JSON incident report generator.

Produces a complete structured JSON representation of an incident for
export, intended to be attached to GitHub issues or used for further
processing. Contains the full structured incident representation.
"""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from tb_core.core.models import Incident, Event, Evidence


class JSONReporter:
    """Generate a JSON report for an incident."""

    def generate(self, report: Dict[str, Any], output_path: Optional[str] = None) -> str:
        data = self._build_report(report)
        payload = self._to_json(data, indent=2)
        if output_path:
            Path(output_path).write_text(payload, encoding="utf-8")
        return payload

    def write_json_report(self, report: Dict[str, Any], output_path: str):
        Path(output_path).write_text(self.generate(report), encoding="utf-8")

    def generate_report(self, report: Dict[str, Any]) -> str:
        return self._to_json(self._build_report(report))

    def _build_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        incident = report["incident"]
        return {
            "incident_id": incident.incident_id,
            "title": report["title"],
            "severity": report["severity"],
            "confidence": report["confidence"],
            "start_time": (
                report["start_time"].isoformat()
                if hasattr(report["start_time"], "isoformat")
                else report["start_time"]
            )
            if report["start_time"]
            else None,
            "end_time": (
                report["end_time"].isoformat()
                if hasattr(report["end_time"], "isoformat")
                else report["end_time"]
            )
            if report["end_time"]
            else None,
            "primary_error": report["primary_error"],
            "affected_services": report.get("affected_services", []),
            "related_events_count": len(incident.related_events),
            "summary": report["summary"],
            "cascade_chain": [
                {
                    "finding": ev.finding,
                    "event_id": ev.event_ids[0] if ev.event_ids else None,
                    "source_file": ev.source_file,
                    "line_number": ev.line_number,
                    "confidence": ev.confidence,
                    "is_observed": ev.is_observed,
                }
                for ev in report.get("cascade_chain", [])
            ],
            "recommendations": report.get("recommendations", []),
            "evidence": [
                {
                    "finding": ev.finding,
                    "event_id": ev.event_ids[0] if ev.event_ids else None,
                    "source_file": ev.source_file,
                    "line_number": ev.line_number,
                    "confidence": ev.confidence,
                    "is_observed": ev.is_observed,
                }
                for ev in report.get("evidence", [])
            ],
            "analysis_metadata": {
                "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            },
            "events": [
                {
                    "event_id": ev.event_id,
                    "timestamp": ev.timestamp.isoformat(),
                    "level": ev.level,
                    "message": ev.message,
                    "service": ev.service,
                    "request_id": ev.request_id,
                    "trace_id": ev.trace_id,
                    "source_file": ev.source_file,
                    "line_number": ev.line_number,
                    "exception_type": ev.exception_type,
                }
                for ev in incident.related_events
            ],
        }

    @staticmethod
    def _to_json(obj: Any, indent: int = 2) -> str:
        import json
        return json.dumps(obj, indent=indent, ensure_ascii=False)
