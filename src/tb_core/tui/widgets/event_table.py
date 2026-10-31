"""Event table widget for the TUI."""

from __future__ import annotations

from typing import List, Optional

from textual.app import ComposeResult
from textual.widgets import DataTable
from textual.widget import Widget

from tb_core.core.models import Event


class EventTable(Widget):
    """A table of log events with sortable columns."""

    def __init__(self, events: Optional[List[Event]] = None, **kwargs):
        super().__init__(**kwargs)
        self._events: List[Event] = events or []
        self._table = DataTable(id="event-table", zebra_stripes=True)

    def compose(self) -> ComposeResult:
        yield self._table

    def on_mount(self) -> None:
        self._table.add_columns("Time", "Level", "Service", "Request ID", "Message")
        self._table.cursor_type = "row"
        self.refresh_events()

    def refresh_events(self, events: Optional[List[Event]] = None) -> None:
        """Replace the table contents with a new event list."""
        if events is not None:
            self._events = events
        self._table.clear()
        for ev in self._events:
            from tb_core.utils.timestamps import format_timestamp
            ts = format_timestamp(ev.timestamp)
            level = ev.level
            service = ev.service or "-"
            rid = ev.request_id or "-"
            msg = ev.message[:90]
            self._table.add_row(ts, level, service, rid, msg, key=ev.event_id)

    def get_selected_event(self) -> Optional[Event]:
        """Return the event at the current cursor row, if any."""
        if not self._events:
            return None
        row = self._table.cursor_row
        if row is None or row < 0 or row >= len(self._events):
            return None
        return self._events[row]
