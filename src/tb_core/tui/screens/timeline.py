"""Timeline viewer screen — chronological event sequence for an incident."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Vertical, ScrollableContainer
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static, Label

from tb_core.core.models import Event
from tb_core.core.timeline import Timeline
from tb_core.utils.timestamps import format_timestamp
from tb_core.utils.helpers import severity_color


class TimelineScreen(Screen):
    """Timeline viewer showing chronological events for the selected incident."""

    CSS_PATH = "../styles.tcss"

    def compose(self) -> ComposeResult:
        yield Header()
        inc_id = getattr(self.app, "selected_incident_id", None)
        yield Static(f"Timeline — {inc_id or 'unknown'}", id="title")
        yield Static("Chronological event reconstruction", id="subtitle")

        inc = self._find_incident(inc_id)
        if inc is None:
            yield Static("Incident not found.", id="empty-state", classes="empty")
            yield Static("Press 'i' to return to incidents", id="help")
            yield Footer()
            return

        timeline = Timeline().build(inc.related_events)
        events_data = timeline["events"]

        yield Label("Timeline", classes="section-label")
        table = DataTable(id="timeline-table", zebra_stripes=True)
        table.add_columns("Time", "Marker", "Level", "Service", "Message")
        for item in events_data:
            ev = item["event"]
            marker = item["marker"]
            ts = format_timestamp(ev.timestamp)
            level = ev.level
            service = ev.service or "—"
            msg = ev.message[:70]
            table.add_row(ts, marker, level, service, msg, key=ev.event_id)
        yield table

        yield Static("Press 'i' for incidents, 'v' to view event details", id="help")
        yield Footer()

    def _find_incident(self, inc_id):
        if not inc_id:
            return None
        for inc in self.app.incidents:
            if inc.incident_id == inc_id:
                return inc
        return None

    def on_key(self, event) -> None:
        if event.key == "q":
            self.app.exit()
        elif event.key == "i":
            self.app.switch_screen("incidents")
        elif event.key == "v":
            table = self.query_one("#timeline-table", DataTable)
            row_key = table.cursor_row
            if row_key is not None:
                self.app.selected_event_id = table.rows[row_key].key.value
                self.app.switch_screen("investigation")
