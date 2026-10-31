"""Python stack-trace / traceback parser.

Parses Python traceback output into Event objects. Handles multi-line
stack traces by joining continuation lines until the trace is complete
or the maximum depth is reached.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import List, Optional

from tb_core.core.models import Event

# Example Python log line: 2023-10-27 11:00:10 ERROR [TRC-99] ConnectionTimeout...
FUNCTION_CALL = re.compile(r"^\s*File \"([^\"]+)\", line (\d+), in ([^\n]+)")
EXCEPTION_LINE = re.compile(r"^([A-Za-z][A-Za-z0-9_]*(?:Error|Exception)):?\s*(.*)$", re.IGNORECASE)


class PythonParser:
    """Parse Python stack traces into Event objects."""

    def parse(self, lines: List[str], source_file: Optional[str] = None) -> List[Event]:
        events: List[Event] = []
        current: Optional[Event] = None
        stack_frames: List[str] = []
        pending_exception: Optional[str] = None
        pending_message: Optional[str] = None

        def flush() -> None:
            nonlocal current, stack_frames, pending_exception, pending_message
            if current is not None:
                if stack_frames:
                    current.stack_trace = "\n".join(stack_frames)
                if pending_exception:
                    current.exception_type = pending_exception
                if pending_message:
                    current.message = pending_message
                events.append(current)
            current = None
            stack_frames = []
            pending_exception = None
            pending_message = None

        for line in lines:
            line = line.rstrip("\n")
            if not line.strip():
                continue

            # Traceback header -> start a new traceback block
            if "Traceback" in line:
                flush()
                continue

            # Stack frame: File "path", line N, in func
            fc = FUNCTION_CALL.match(line)
            if fc:
                frame_file, frame_line, frame_func = fc.groups()
                current = Event(
                    event_id=self._make_event_id(source_file),
                    timestamp=datetime.now(),
                    level="ERROR",
                    message=frame_func.strip(),
                    service=None,
                    request_id=None,
                    trace_id=None,
                    session_id=None,
                    source_file=frame_file,
                    line_number=int(frame_line) if frame_line.isdigit() else None,
                    exception_type=None,
                    stack_trace=None,
                    metadata={},
                )
                stack_frames.append(line.strip())
                continue

            # Exception line, e.g. "TypeError: Cannot read properties of null"
            ex = EXCEPTION_LINE.match(line.strip())
            if ex and not line.startswith(" "):
                pending_exception = ex.group(1)
                pending_message = ex.group(2).strip() or ex.group(0)
                flush()
                continue

            # Continuation line of a stack frame
            if current and line.startswith(" ") and stack_frames:
                stack_frames.append(line.strip())
                continue

        flush()
        return events

    @staticmethod
    def _make_event_id(source: Optional[str]) -> str:
        import hashlib
        import time

        raw = f"{source or 'python'}|{time.time_ns()}"
        return hashlib.sha1(raw.encode()).hexdigest()[:16]
