"""Investigation view screen — incident summary, root cause, recommendations."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, ScrollableContainer
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static, Label, Button

from tb_core.core.models import Event
from tb_core.analysis.root_cause import RootCauseAnalyzer
from tb_core.analysis.cascade import CascadeAnalyzer
from tb_core.analysis.recommendations import RecommendationBuilder
from tb_core.core.incident import IncidentGroup as CoreIncidentGroup
from tb_core.utils.timestamps import format_timestamp


class InvestigationScreen(Screen):
    """Investigation view — root cause, evidence, and debugging steps."""

    CSS_PATH = "../styles.tcss"

    def compose(self) -> ComposeResult:
        yield Header()
        inc_id = getattr(self.app, "selected_incident_id", None)
        yield Static(f"Investigation — {inc_id or 'unknown'}", id="title")
        yield Static("Evidence-based root-cause analysis", id="subtitle")

        inc = self._find_incident(inc_id)
        if inc is None:
            yield Static("Incident not found.", id="empty-state", classes="empty")
            yield Static("Press 'i' to return to incidents", id="help")
            yield Footer()
            return

        # Run analysis
        rules_engine = None
        from tb_core.analysis.rules import RulesEngine
        rules_engine = RulesEngine()
        analyzer = RootCauseAnalyzer(rules_engine)
        cascade = CascadeAnalyzer(rules_engine)
        rec_builder = RecommendationBuilder()

        # Wrap incident in IncidentGroup for analysis
        group = CoreIncidentGroup(
            title=inc.title,
            incident_id=inc.incident_id,
            events=inc.related_events,
        )
        analysis = analyzer.analyze(group)
        cascade_chain = cascade.analyze(group)
        recommendations = rec_builder.build(group, cascade_chain, analysis)

        # Left column: summary
        with Vertical(id="left-col"):
            yield Static("Incident Summary", classes="section-label")
            yield Static(analysis.get("summary", "No summary available."), id="incident-summary")
            yield Static("")
            yield Static(f"Confidence: {analysis.get('confidence', 'LOW')}", id="confidence-line")
            yield Static("")
            yield Static("Primary Error", classes="section-label")
            yield Static(inc.primary_error or "—", id="primary-error")
            yield Static("")
            yield Static("Suspected Failure Points", classes="section-label")
            for fp in inc.suspected_failure_points:
                yield Static(f"• {fp}", id="failure-point")
            yield Static("")
            yield Static("Possible Root Causes", classes="section-label")
            for cause in analysis.get("possible_causes", []):
                yield Static(f"• {cause.finding}", id="root-cause")

        # Right column: cascade + recommendations
        with Vertical(id="right-col"):
            yield Static("Cascading Errors", classes="section-label")
            for ce in cascade_chain:
                yield Static(f"• {ce.finding}", id="cascade-item")
            yield Static("")
            yield Static("Suggested Debugging Steps", classes="section-label")
            for i, step in enumerate(recommendations, 1):
                yield Static(f"{i}. {step}", id="recommendation-item")
            yield Static("")
            yield Static("Evidence", classes="section-label")
            for ev in inc.evidence:
                yield Static(f"• {ev.finding} ({ev.confidence})", id="evidence-item")

        yield Static("Press 'i' for incidents, 'r' to export report", id="help")
        yield Footer()

    def _find_incident(self, inc_id):
        if not inc_id:
            return None
        for inc in self.app.incidents:
            if inc.incident_id == inc_id:
                return inc
        return None

    def on_button_pressed(self, event) -> None:
        if event.button.id == "export-report":
            self.app.export_report(inc_id)

    def on_key(self, event) -> None:
        if event.key == "q":
            self.app.exit()
        elif event.key == "i":
            self.app.switch_screen("incidents")
        elif event.key == "r":
            self.app.export_report(inc_id)
