"""Log ingestion engine.

Supports:
  - single .log file
  - multiple log files
  - directory of logs
  - JSON files
  - JSONL files
  - plain-text logs
  - Python stack traces
  - Node.js stack traces

Format detection is automatic, with explicit override support. Large files
are streamed line-by-line rather than fully loaded into memory.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List, Optional

from tb_core.ingestion.detector import FormatDetector
from tb_core.ingestion.json_parser import JsonParser
from tb_core.ingestion.jsonl_parser import JsonlParser
from tb_core.ingestion.text_parser import TextParser
from tb_core.ingestion.python_parser import PythonParser
from tb_core.ingestion.node_parser import NodeParser
from tb_core.core.models import Event

_PARSERS = {
    "json": JsonParser(),
    "jsonl": JsonlParser(),
    "text": TextParser(),
    "python": PythonParser(),
    "node": NodeParser(),
}


class LogLoader:
    """Streams logs and normalises them into Event objects."""

    def load(self, file_path: str, fmt: Optional[str] = None) -> List[Event]:
        detector = FormatDetector()
        resolved = detector.detect(file_path, fmt or "auto")

        path = Path(file_path)
        if path.is_dir():
            return self._load_directory(path, resolved)
        return self._load_file(path, resolved)

    def load_dir(self, directory_path: str) -> List[Event]:
        detector = FormatDetector()
        events: List[Event] = []
        directory = Path(directory_path)
        for f in self._iter_files(directory):
            resolved = detector.detect(str(f), "auto")
            events.extend(self._load_file(f, resolved))
        return events

    def _load_directory(self, directory: Path, fmt: str) -> List[Event]:
        events: List[Event] = []
        files = self._iter_files(directory)
        for f in files:
            events.extend(self._load_file(f, fmt))
        return events

    def _iter_files(self, directory: Path) -> List[Path]:
        exts = {".log", ".txt", ".json", ".jsonl"}
        return [p for p in directory.iterdir() if p.is_file() and p.suffix.lower() in exts]

    def _load_file(self, path: Path, fmt: str) -> List[Event]:
        parser = _PARSERS.get(fmt)
        if parser is None:
            parser = TextParser()

        if fmt == "json":
            with open(path, encoding="utf-8", errors="replace") as fh:
                return parser.parse(json.load(fh), str(path))
        if fmt == "jsonl":
            return parser.parse_file(str(path))
        if fmt in ("python", "node"):
            return self._stream_traceback(str(path), fmt, parser)
        return self._stream_text(str(path), parser)

    def _stream_text(self, path: str, parser: TextParser) -> List[Event]:
        events: List[Event] = []
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                ev = parser.parse_line(line, source_file=str(path))
                if ev:
                    events.append(ev)
        return events

    def _stream_traceback(self, path: str, fmt: str, parser) -> List[Event]:
        events: List[Event] = []
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        return parser.parse(lines, source_file=path)