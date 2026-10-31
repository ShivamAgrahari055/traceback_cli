"""Node.js stack-trace / exception parser.

Parses Node.js stack traces and error output into Event objects.
Handles multi-line traces with frames starting with "at ...".
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import List, Optional

from tb_core.core.models import Event

# Node.js stack frame: at func (file.js:12:3)
NODE_FRAME = re.compile(r"^\s+at\s+(.+?)\s+\(([^:]+):(\d+)(?::(\d+))?\)")
# Example log line: 2023-10-27 10:30:06 ERROR [REQ-101] TypeError: Cannot read properties of null

STACK_START = re.compile(r"^at\s+\S+\s+\(", re.IGNORECASE)


class NodeParser:
    """Parse Node.js stack traces into Event objects."""

    def parse(self, lines: List[str], source_file: Optional[str] = None) -> List[Event]:
        events: List[Event] = []
        event: Optional[Event] = None

        for line in lines:
            line = line.rstrip("\n")

            # Node frame
            fr = NODE_FRAME.match(line)
            if fr:
                if event:
                    events.append(event)
                func, filepath, line_no, _col = fr.groups()
                event = Event(
                    event_id=self._make_event_id(source_file),
                    timestamp=datetime.now(),
                    level="ERROR",
                    message=func.strip(),
                    service=None,
                    request_id=None,
                    trace_id=None,
                    session_id=None,
                    source_file=filepath,
                    line_number=int(line_no),
                    exception_type="Error",
                    stack_trace=f"at {func.strip()} ({filepath}:{line_no})",
                    metadata={},
                )
                continue

            # Stack trace starting keyword
            if "Error" in line and (" at " in line or "at" in line):
                if event:
                    events.append(event)
                    event = None
                continue

            # Continuation of a stack frame
            if event and STACK_START.match(line):
                if event.stack_trace is None:
                    event.stack_trace = ""
                if line.strip():
                    event.stack_trace += "\n  " + line.strip()

        if event:
            events.append(event)
        return events

    @staticmethod
    def _make_event_id(source: Optional[str]) -> str:
        import hashlib
        raw = f"{source or 'node'}|{_trace_counter()}"
        return hashlib.sha1(raw.encode()).hexdigest()[:16]


_counter = [0]


def _trace_counter() -> int:
    _counter[0] += 1
    return _counter[0]