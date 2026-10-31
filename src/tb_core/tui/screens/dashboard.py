"""Dashboard screen — high-level overview of processed logs and incidents."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static, Label

from tb_core.core.models import Event, Incident
from tb_core.utils.timestamps import format_timestamp
from tb_core.utils.helpers import count_by_level, group_by_service


class DashboardScreen(Screen):
    """Main dashboard showing event/incident statistics."""

    CSS_PATH = "../styles.tcss"

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("TraceBack Dashboard", id="title")
        yield Static("Local-first incident analysis", id="subtitle")

        with Horizontal(id="stats-row"):
            yield Static(self._stat_panel("Events", str(len(self.app.events)), "#38bdf8"), id="stat-events")
            yield Static(self._stat_panel("Incidents", str(len(self.app.incidents)), "#fbbf24"), id="stat-incidents")
            critical = sum(1 for i in self.app.incidents if i.severity == "CRITICAL")
            yield Static(self._stat_panel("Critical", str(critical), "#f87171"), id="stat-critical")
            errors = count_by_level(self.app.events).get("ERROR", 0)
            yield Static(self._stat_panel("Errors", str(errors), "#f87171"), id="stat-errors")

        yield Label("Recent Incidents", classes="section-label")
        table = DataTable(id="incidents-table", zebra_stripes=True)
        table.add_columns("ID", "Severity", "Start", "Primary Error")
        for inc in self.app.incidents[:10]:
            table.add_row(
                inc.incident_id,
                inc.severity,
                format_timestamp(inc.start_time) if inc.start_time else "—",
                (inc.primary_error or "—")[:60],
                key=inc.incident_id,
            )
        yield table

        services = group_by_service(self.app.events)
        yield Label("Services Involved", classes="section-label")
        with Vertical(id="services-list"):
            for svc in sorted(services):
                yield Static(f"{svc}: {len(services[svc])} events", id=f"svc-{svc}")

        yield Static("Press 'q' to quit, 'i' for incidents, 't' for timeline", id="help")
        yield Footer()

    def _stat_panel(self, label: str, value: str, color: str) -> str:
        return f"[{color}]{value}[/{color}]\n{label}"

    def on_key(self, event) -> None:
        if event.key == "q":
            self.app.exit()
        elif event.key == "i":
            self.app.switch_screen("incidents")
        elif event.key == "t":
            self.app.switch_screen("timeline")
