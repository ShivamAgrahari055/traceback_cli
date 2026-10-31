"""Incident explorer screen — list and filter incidents."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static, Input, Select, Button

from tb_core.core.models import Incident
from tb_core.utils.timestamps import format_timestamp


class IncidentsScreen(Screen):
    """Explorer showing all incidents with filtering."""

    CSS_PATH = "../styles.tcss"

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Incident Explorer", id="title")
        yield Static("Browse, filter, and select incidents", id="subtitle")

        with Horizontal(id="filter-row"):
            yield Static("Severity:", id="sev-label")
            yield Select(
                [
                    ("All", "all"),
                    ("CRITICAL", "CRITICAL"),
                    ("ERROR", "ERROR"),
                    ("WARNING", "WARNING"),
                    ("INFO", "INFO"),
                    ("DEBUG", "DEBUG"),
                ],
                value="all",
                id="sev-filter",
            )
            yield Static("Service:", id="svc-label")
            yield Input(placeholder="filter by service...", id="svc-filter")
            yield Button("Apply", id="apply-filter", variant="primary")

        yield Static("Incidents", classes="section-label")
        table = DataTable(id="incidents-table", zebra_stripes=True)
        table.add_columns("ID", "Severity", "Start", "Service", "Primary Error", "Events")
        self._populate_table(table)
        yield table

        yield Static("Press 'd' for dashboard, Enter to view incident", id="help")
        yield Footer()

    def _populate_table(self, table) -> None:
        incidents = self.app.incidents
        sev_select = self.query_one("#sev-filter", Select)
        svc_input = self.query_one("#svc-filter", Input)
        sev = sev_select.value
        svc = svc_input.value.strip().lower()
        for inc in incidents:
            if sev != "all" and inc.severity != sev:
                continue
            if svc and svc not in (s.lower() for s in inc.affected_services):
                continue
            table.add_row(
                inc.incident_id,
                inc.severity,
                format_timestamp(inc.start_time) if inc.start_time else "—",
                (inc.affected_services[0] if inc.affected_services else "—"),
                (inc.primary_error or "—")[:50],
                str(len(inc.related_events)),
                key=inc.incident_id,
            )

    def on_button_pressed(self, event) -> None:
        if event.button.id == "apply-filter":
            table = self.query_one("#incidents-table", DataTable)
            table.clear()
            self._populate_table(table)

    def on_data_table_row_selected(self, event) -> None:
        row_key = event.row_key.value
        self.app.selected_incident_id = row_key
        self.app.switch_screen("investigation")

    def on_key(self, event) -> None:
        if event.key == "q":
            self.app.exit()
        elif event.key == "d":
            self.app.switch_screen("dashboard")
