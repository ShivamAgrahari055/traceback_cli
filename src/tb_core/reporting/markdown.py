"""Markdown incident report generator.

Produces a human-readable Markdown report suitable for attaching to GitHub
issues or sharing with a team. Every finding is traceable to an original
log entry.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from tb_core.core.models import Incident


class MarkdownReporter:
    """Generate a Markdown report for an incident."""

    def generate(self, report: Dict[str, Any]) -> str:
        incident: Incident = report["incident"]
        lines: List[str] = []

        lines.append(f"# Incident Report: {incident.incident_id}")
        lines.append(f"**Title:** {incident.title}")
        lines.append("")
        lines.append(f"**Severity:** {report.get('severity', 'INFO')}")
        lines.append(f"**Confidence:** {report.get('confidence', 'MEDIUM')}")
        lines.append(f"**Start time:** {report.get('start_time')}")
        lines.append(f"**End time:** {report.get('end_time')}")
        lines.append(f"**Primary error:** {report.get('primary_error') or 'None'}")
        lines.append(f"**Affected services:** {', '.join(report.get('affected_services', [])) or 'None'}")
        lines.append("")

        summary = report.get("summary")
        if summary:
            lines.append("## Summary")
            lines.append("")
            lines.append(summary)
            lines.append("")

        lines.append("## Timeline")
        lines.append("")
        events = report.get("events", [])
        for i, ev in enumerate(events, 1):
            ts = ev.timestamp.isoformat() if hasattr(ev, "timestamp") else ev.get("timestamp")
            level = ev.level if hasattr(ev, "level") else ev.get("level")
            message = ev.message if hasattr(ev, "message") else ev.get("message")
            service = ev.service if hasattr(ev, "service") else ev.get("service")
            lines.append(f"{i}. [{ts}] **{level}** [{service or 'unknown'}] {message}")
        lines.append("")

        root_cause = report.get("root_cause")
        if root_cause:
            lines.append("## Root-Cause Analysis")
            lines.append("")
            lines.append(f"**Title:** {root_cause.get('title', 'N/A')}")
            lines.append(f"**Confidence:** {root_cause.get('confidence', 'N/A')}")
            lines.append("")
            if root_cause.get("summary"):
                lines.append(root_cause["summary"])
                lines.append("")
            if root_cause.get("primary_error"):
                lines.append(f"**Primary error:** {root_cause['primary_error']}")
                lines.append("")
            if root_cause.get("suspicious_event"):
                sev = root_cause["suspicious_event"]
                lines.append("### First suspicious event")
                lines.append("")
                msg = sev.message if hasattr(sev, "message") else sev.get("message", "N/A")
                src = sev.source_file if hasattr(sev, "source_file") else sev.get("source_file")
                line = sev.line_number if hasattr(sev, "line_number") else sev.get("line_number")
                lines.append(f"- {msg}")
                if src:
                    lines.append(f"  Source: {src}:{line}" if line else f"  Source: {src}")
                lines.append("")

        evidence = report.get("evidence", [])
        if evidence:
            lines.append("## Supporting Evidence")
            lines.append("")
            for ev in evidence:
                lines.append(f"- {ev.finding if hasattr(ev, 'finding') else ev.get('finding')} "
                             f"(confidence: {ev.confidence if hasattr(ev, 'confidence') else ev.get('confidence', 'MEDIUM')})")
            lines.append("")

        cascade = report.get("cascade_chain", [])
        if cascade:
            lines.append("## Cascading Errors")
            lines.append("")
            for ev in cascade:
                lines.append(f"- {ev.finding if hasattr(ev, 'finding') else ev.get('finding')}")
            lines.append("")

        recommendations = report.get("recommendations", [])
        if recommendations:
            lines.append("## Suggested Debugging Steps")
            lines.append("")
            for i, step in enumerate(recommendations, 1):
                lines.append(f"{i}. {step}")
            lines.append("")

        lines.append("## Analysis Limitations")
        lines.append("")
        lines.append("- This analysis is deterministic and rule-based; it does not use an LLM unless enabled.")
        lines.append("- Correlation relies on request/trace IDs and timestamp proximity; events without identifiers may be missed.")
        lines.append("- Timestamps are assumed UTC when timezone-naive (see configuration).")
        lines.append("- Secret values have been redacted with [REDACTED].")
        lines.append("")

        return "\n".join(lines)

    def write_markdown_report(self, report: Dict[str, Any], output_path: str) -> None:
        Path(output_path).write_text(self.generate(report), encoding="utf-8")
