"""TraceBack Textual TUI application.

The main app wires together the ingestion pipeline and the four screens:
dashboard, incident explorer, timeline viewer, and investigation view.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional

import typer
from textual.app import App, ComposeResult
from textual.screen import Screen

from tb_core.ingestion.loader import LogLoader
from tb_core.ingestion.detector import FormatDetector
from tb_core.core.normalizer import Normalizer
from tb_core.core.correlator import IncidentCorrelator
from tb_core.core.incident import IncidentGroup as CoreIncidentGroup
from tb_core.core.models import Event, Incident
from tb_core.security.redactor import SecretRedactor
from tb_core.storage.database import IncidentDatabase
from tb_core.reporting.markdown import MarkdownReporter
from tb_core.reporting.json_report import JSONReporter
from tb_core.tui.screens.dashboard import DashboardScreen
from tb_core.tui.screens.incidents import IncidentsScreen
from tb_core.tui.screens.timeline import TimelineScreen
from tb_core.tui.screens.investigation import InvestigationScreen


class TraceBackApp(App):
    """TraceBack TUI application."""

    CSS_PATH = "styles.tcss"

    def __init__(
        self,
        log_path: Optional[str] = None,
        fmt: str = "auto",
        redact: bool = True,
        db_path: str = "traceback_history.db",
    ):
        super().__init__()
        self.log_path = log_path
        self.fmt = fmt
        self.redact = redact
        self.db_path = db_path
        self.events: List[Event] = []
        self.incidents: List[Incident] = []
        self.selected_incident_id: Optional[str] = None

    def compose(self) -> ComposeResult:
        # Screens are installed in on_mount after data is loaded
        yield from []

    def on_mount(self) -> None:
        if self.log_path:
            self._load_and_analyse(self.log_path)
        else:
            # Load any existing incidents from history
            self._load_history()

        self.install_screen(DashboardScreen(self.events, self.incidents), name="dashboard")
        self.install_screen(IncidentsScreen(self.incidents), name="incidents")
        self.switch_screen("dashboard")

    def _load_and_analyse(self, path: str) -> None:
        detector = FormatDetector()
        resolved = detector.detect(path, self.fmt)

        loader = LogLoader()
        path_obj = Path(path)
        if path_obj.is_dir():
            raw_events = loader.load_dir(str(path_obj))
        else:
            raw_events = loader.load(str(path), fmt=resolved)

        if self.redact:
            redactor = SecretRedactor()
            for e in raw_events:
                e.message = redactor.redact_event_message(e.message)
                e.stack_trace = redactor.redact_stack_trace(e.stack_trace)

        normalizer = Normalizer(assume_utc=True)
        self.events = normalizer.normalise(raw_events, source=path)

        correlator = IncidentCorrelator()
        correlated = correlator.correlate(self.events)

        grouped = CoreIncidentGroup().group_incidents(correlated)
        for g in grouped:
            inc = Incident(
                incident_id=g.incident_id,
                title=g.title,
                severity=g.best_severity(
                    {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}
                ),
                start_time=g.start_time,
                end_time=g.end_time,
                related_events=list(g.events),
                affected_services=list(g.affected_services),
                confidence="MEDIUM",
                evidence=list(g.evidence),
            )
            self.incidents.append(inc)

        # Persist to history
        try:
            db = IncidentDatabase(self.db_path)
            for inc in self.incidents:
                db.save_incident(
                    incident_id=inc.incident_id,
                    title=inc.title,
                    severity=inc.severity,
                    summary=f"{len(inc.related_events)} events across {len(inc.affected_services)} service(s)",
                    events=inc.related_events,
                    start_time=inc.start_time,
                    end_time=inc.end_time,
                    primary_error=inc.primary_error,
                    affected_services=inc.affected_services,
                    confidence=inc.confidence,
                )
        except Exception:
            pass  # History persistence is best-effort

    def _load_history(self) -> None:
        try:
            db = IncidentDatabase(self.db_path)
            rows = db.get_all_incidents()
            for row in rows:
                inc = Incident(
                    incident_id=row["id"],
                    title=row["title"] or "Untitled incident",
                    severity=row["severity"] or "INFO",
                    start_time=None,
                    end_time=None,
                    related_events=[],
                    affected_services=[],
                    confidence=row["confidence"] or "MEDIUM",
                    evidence=[],
                )
                self.incidents.append(inc)
        except Exception:
            pass

    def export_report(self, incident_id: Optional[str] = None, fmt: str = "markdown") -> None:
        """Export a report for the given incident."""
        inc_id = incident_id or self.selected_incident_id
        if not inc_id:
            return

        inc = None
        for i in self.incidents:
            if i.incident_id == inc_id:
                inc = i
                break
        if inc is None:
            return

        from tb_core.analysis.rules import RulesEngine
        from tb_core.analysis.root_cause import RootCauseAnalyzer
        from tb_core.analysis.cascade import CascadeAnalyzer
        from tb_core.analysis.recommendations import RecommendationBuilder
        from tb_core.core.incident import IncidentGroup as CoreIncidentGroup

        rules_engine = RulesEngine()
        analyzer = RootCauseAnalyzer(rules_engine)
        cascade = CascadeAnalyzer(rules_engine)
        rec_builder = RecommendationBuilder()

        group = CoreIncidentGroup(
            title=inc.title,
            incident_id=inc.incident_id,
            events=inc.related_events,
        )
        analysis = analyzer.analyze(group)
        cascade_chain = cascade.analyze(group)
        recommendations = rec_builder.build(group, cascade_chain, analysis)

        report = {
            "incident": inc,
            "title": analysis.get("title", inc.title),
            "severity": inc.severity,
            "summary": analysis.get("summary", ""),
            "root_cause": analysis,
            "cascade_chain": cascade_chain,
            "recommendations": recommendations,
            "evidence": inc.evidence,
            "events": inc.related_events,
            "start_time": inc.start_time,
            "end_time": inc.end_time,
            "primary_error": inc.primary_error,
            "affected_services": inc.affected_services,
            "confidence": analysis.get("confidence", "MEDIUM"),
        }

        out_path = f"traceback_report_{inc_id}.{fmt}"
        if fmt == "json":
            reporter = JSONReporter()
            reporter.write_json_report(report, out_path)
        else:
            reporter = MarkdownReporter()
            reporter.write_markdown_report(report, out_path)

        typer.echo(f"Report exported to {out_path}")


def run_tui(
    log_path: Optional[str] = None,
    fmt: str = "auto",
    redact: bool = True,
    db_path: str = "traceback_history.db",
) -> None:
    app = TraceBackApp(log_path=log_path, fmt=fmt, redact=redact, db_path=db_path)
    app.run()


if __name__ == "__main__":
    run_tui()
