"""Error panel widget — displays exception details and stack traces."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import Static

from tb_core.core.models import Event


class ErrorPanel(Widget):
    """Displays a single error event with its stack trace."""

    def __init__(self, event: Optional[Event] = None, **kwargs):
        super().__init__(**kwargs)
        self._event = event

    def compose(self) -> ComposeResult:
        self._static = Static(id="log-detail")
        yield self._static
        self.refresh()

    def set_event(self, event: Optional[Event]) -> None:
        self._event = event
        self.refresh()

    def refresh(self) -> None:
        if self._static is None:
            return
        if self._event is None:
            self._static.update("No event selected.")
            return
        lines = [
            f"Event ID:   {self._event.event_id}",
            f"Time:       {self._event.timestamp}",
            f"Level:      {self._event.level}",
            f"Service:    {self._event.service or 'unknown'}",
            f"Request ID: {self._event.request_id or '—'}",
            f"Trace ID:   {self._event.trace_id or '—'}",
            f"Source:     {self._event.source_file or 'unknown'}",
            f"Line:       {self._event.line_number or '—'}",
            f"Exception:  {self._event.exception_type or '—'}",
            "",
            "Message:",
            self._event.message,
            "",
        ]
        if self._event.stack_trace:
            lines.append("Stack Trace:")
            lines.append(self._event.stack_trace)
        self._static.update("\n".join(lines))
