"""JSONL (newline-delimited JSON) log parser.

Each non-empty line is a JSON object representing one log event.
Malformed lines are skipped with a warning; parsing never crashes.
"""

from __future__ import annotations

from typing import List, Optional

from tb_core.ingestion.json_parser import JsonParser
from tb_core.core.models import Event


class JsonlParser(JsonParser):
    """Parse newline-delimited JSON logs."""

    def parse_file(self, path: str) -> List[Event]:
        events: List[Event] = []
        with open(path, encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    obj = self._safe_json_load(line)
                except Exception:
                    continue
                if isinstance(obj, dict):
                    try:
                        ev = self._item_to_event(obj, path)
                        if ev:
                            ev.line_number = lineno
                            events.append(ev)
                    except Exception:
                        continue
        return events

    @staticmethod
    def _safe_json_load(line: str):
        import json
        return json.loads(line)