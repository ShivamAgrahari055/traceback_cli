"""JSON log parser.

Parses log files where each line (or the whole file) is a JSON record.
Supports both newline-delimited JSON (JSONL) and a JSON array of records.
Records are mapped to the Event model; unknown fields are preserved in
metadata and never cause parsing failures.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from tb_core.core.models import Event

TIMESTAMP_FIELDS = ("timestamp", "time", "ts", "datetime", "date")
LEVEL_FIELDS = ("level", "severity", "loglevel", "priority")
MESSAGE_FIELDS = ("message", "msg", "text", "description", "event")
SERVICE_FIELDS = ("service", "service_name", "source", "app", "component")
REQUEST_FIELDS = ("request_id", "requestId", "request_id")
TRACE_FIELDS = ("trace_id", "traceId", "traceId", "trace")
SESSION_FIELDS = ("session_id", "sessionId", "session")

# Common timestamp formats encountered in JSON logs.
TIMESTAMP_FORMATS: List[str] = [
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",
    "%b %d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
]


class JsonParser:
    """Parse JSON logs into Event objects."""

    def parse(self, data: Any, source_file: Optional[str] = None) -> List[Event]:
        events: List[Event] = []

        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            return events

        for item in data:
            if not isinstance(item, dict):
                continue
            try:
                ev = self._item_to_event(item, source_file)
                if ev:
                    events.append(ev)
            except Exception:
                continue
        return events

    def parse_lines(self, lines: List[str], source_file: Optional[str] = None) -> List[Event]:
        events: List[Event] = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                try:
                    ev = self._item_to_event(obj, source_file)
                    if ev:
                        events.append(ev)
                except Exception:
                    continue
        return events

    def _item_to_event(self, obj: Dict[str, Any], source_file: Optional[str]) -> Optional[Event]:
        ts = self._get_timestamp(obj)
        level = self._get_level(obj)
        message = self._get_message(obj)
        if not ts or not message:
            return None

        return Event(
            event_id=self._get_event_id(obj),
            timestamp=ts,
            level=level,
            message=message,
            service=self._get_field(obj, SERVICE_FIELDS),
            request_id=self._get_field(obj, REQUEST_FIELDS),
            trace_id=self._get_field(obj, TRACE_FIELDS),
            session_id=self._get_field(obj, SESSION_FIELDS),
            source_file=source_file,
            line_number=None,
            exception_type=self._get_field(obj, ("exception_type", "exception", "type")),
            stack_trace=self._get_field(obj, ("stack_trace", "stack", "traceback")),
            metadata=self._get_metadata(obj),
        )

    @staticmethod
    def _get_field(obj: Dict[str, Any], fields: tuple) -> Any:
        for f in fields:
            if f in obj:
                return obj[f]
        return None

    @staticmethod
    def _get_event_id(obj: Dict[str, Any]) -> str:
        for f in ("event_id", "id", "eventId"):
            if f in obj:
                return str(obj[f])
        return ""

    @staticmethod
    def _get_timestamp(obj: Dict[str, Any]) -> Optional[datetime]:
        for f in TIMESTAMP_FIELDS:
            if f in obj and obj[f] is not None:
                val = obj[f]
                if isinstance(val, datetime):
                    return val
                return JsonParser._parse_timestamp(str(val))
        return None

    @staticmethod
    def _parse_timestamp(val: str) -> Optional[datetime]:
        for fmt in TIMESTAMP_FORMATS:
            try:
                return datetime.strptime(val, fmt)
            except ValueError:
                continue
        # Last resort: pydantic-friendly ISO parse.
        try:
            return datetime.fromisoformat(val.replace("Z", "+00:00"))
        except ValueError:
            return None

    @staticmethod
    def _get_level(obj: Dict[str, Any]) -> str:
        val = JsonParser._get_field(obj, LEVEL_FIELDS)
        if val is None:
            return "INFO"
        return str(val).upper()

    @staticmethod
    def _get_message(obj: Dict[str, Any]) -> Optional[str]:
        val = JsonParser._get_field(obj, MESSAGE_FIELDS)
        if val is None:
            return None
        return str(val)

    @staticmethod
    def _get_metadata(obj: Dict[str, Any]) -> Dict[str, Any]:
        metadata: Dict[str, Any] = {}
        skip = set(TIMESTAMP_FIELDS + LEVEL_FIELDS + MESSAGE_FIELDS +
                   SERVICE_FIELDS + REQUEST_FIELDS + TRACE_FIELDS + SESSION_FIELDS +
                   ("event_id", "id", "stack_trace", "exception_type", "exception", "type"))
        for k, v in obj.items():
            if k not in skip:
                metadata[k] = v
        return metadata