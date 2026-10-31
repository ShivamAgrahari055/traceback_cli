import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from tb_core.core.models import Event, LOG_LEVELS

# Example: 2023-10-27 10:30:01 INFO [REQ-101] Server started
LINE_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(\w+)\s+(.*)$"
)
BRACKET_ID_PATTERN = re.compile(r"\[([A-Z0-9_-]+)\]")
REQUEST_ID_HINT = re.compile(r"(?:request[_-]?id|req)[=:]\s*([A-Za-z0-9_-]+)", re.IGNORECASE)


class TextParser:
    """Parse free-form single-line-per-record log text into Event objects."""

    def parse_line(self, line: str, source_file: str = "") -> Optional[Event]:
        """Parse a single log line into an Event.

        Returns None for empty, comment, or unparseable lines.
        """
        match = LINE_PATTERN.match(line.strip())
        if not match:
            return None

        ts_str, level, rest = match.groups()

        # Only recognise canonical log levels; anything else is not a log record.
        if level.upper() not in LOG_LEVELS:
            return None

        # Pull a leading [REQ-101]-style id out of the message as the request_id.
        request_id = None
        bid = BRACKET_ID_PATTERN.match(rest)
        if bid:
            request_id = bid.group(1)
            rest = rest[bid.end():].strip()
        if not request_id:
            m = REQUEST_ID_HINT.search(rest)
            if m:
                request_id = m.group(1)

        try:
            ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None

        try:
            return Event(
                event_id=self._make_event_id(source_file, line),
                timestamp=ts,
                level=level.upper(),
                message=rest,
                source_file=Path(source_file).name if source_file else None,
                request_id=request_id,
            )
        except Exception:
            return None

    @staticmethod
    def _make_event_id(source_file: str, line: str) -> str:
        import hashlib

        raw = f"{source_file}|{line[:60]}"
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]
