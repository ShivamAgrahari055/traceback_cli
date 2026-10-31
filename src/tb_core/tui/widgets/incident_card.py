"""Incident card widget — summary card for a single incident."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static

from tb_core.core.models import Incident


class IncidentCard(Widget):
    """A compact card showing incident summary information."""

    def __init__(self, incident: Optional[Incident] = None, **kwargs):
        super().__init__(**kwargs)
        self._incident = incident

    def compose(self) -> ComposeResult:
        self._static = Static(id="incident-card")
        yield self._static
        self.refresh()

    def set_incident(self, incident: Optional[Incident]) -> None:
        self._incident = incident
        self.refresh()

    def refresh(self) -> None:
        if self._static is None:
            return
        if self._incident is None:
            self._static.update("No incident selected.")
            return
        inc = self._incident
        lines = [
            f"ID:        {inc.incident_id}",
            f"Title:     {inc.title}",
            f"Severity:  {inc.severity}",
            f"Confidence:{inc.confidence}",
            f"Start:     {inc.start_time}",
            f"End:       {inc.end_time}",
            f"Services:  {', '.join(inc.affected_services) or '—'}",
            f"Events:    {len(inc.related_events)}",
        ]
        if inc.primary_error:
            lines.append("")
            lines.append(f"Primary error: {inc.primary_error}")
        self._static.update("\n".join(lines))
