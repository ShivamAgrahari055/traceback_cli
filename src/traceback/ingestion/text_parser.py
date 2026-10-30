import re
from datetime import datetime
from traceback.core.models import Event

class TextParser:
    def __init__(self):
        # Basic regex for: TIMESTAMP LEVEL MESSAGE
        # Example: 2023-10-27 10:30:01 INFO User lookup started
        self.pattern = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(\w+)\s+(.*)$')

    def parse_line(self, line: str):
        match = self.pattern.match(line.strip())
        if match:
            ts_str, level, msg = match.groups()
            try:
                return Event(
                    timestamp=datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S'),
                    level=level,
                    message=msg
                )
            except Exception:
                return None
        return None
