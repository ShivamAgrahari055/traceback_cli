"""Log format detection.

TraceBack supports several input formats. This module inspects a file's
content and returns the best-matching format:

    auto   -> detect automatically
    json   -> a JSON array of log records
    jsonl  -> newline-delimited JSON (one record per line)
    text   -> free-form single-line-per-record log text
    python -> Python stack-trace / traceback text
    node   -> Node.js stack-trace / exception text
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

TEXT_LINE_MATCH = 0.5
JSONL_LINE_MATCH = 0.7
JSON_ARRAY_MATCH = 0.8


class FormatDetector:
    KNOWN_FORMATS = ("auto", "json", "jsonl", "text", "python", "node")

    JSON_KEYWORDS = (
        '"timestamp"', '"level"', '"message"', '"service"', '"request_id"',
        '"trace_id"', '"exception_type"', '"stack_trace"', '"msg"', '"event"',
    )

    PYTHON_STACK_MARKERS = ("Traceback", 'File "', "line ", "Traceback (most recent call last)")
    NODE_STACK_MARKERS = ("at ", "Error", "ReferenceError", "TypeError", "RangeError")

    def detect(self, file_path: str, explicit: str = "auto") -> str:
        if explicit != "auto":
            self._validate(explicit)
            return explicit

        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Log source not found: {file_path}")

        if path.is_dir():
            return self._detect_directory(path)

        return self._detect_file(path)

    def _validate(self, fmt: str) -> None:
        if fmt not in self.KNOWN_FORMATS:
            raise ValueError(f"Unknown format '{fmt}'")

    def _detect_directory(self, directory: Path) -> str:
        counts = {f: 0 for f in self.KNOWN_FORMATS}
        files = self._iter_log_files(directory)
        for f in files:
            counts[self._detect_file(f)] += 1
        if not files:
            return "text"
        return max(counts, key=counts.get)

    def _iter_log_files(self, directory: Path) -> List[Path]:
        exts = {".log", ".txt", ".json", ".jsonl"}
        return [p for p in directory.iterdir() if p.is_file() and p.suffix.lower() in exts]

    def _detect_file(self, path: Path) -> str:
        suffix = path.suffix.lower()
        if suffix == ".json":
            return self._probe_json_array(path)
        if suffix == ".jsonl":
            return self._probe_jsonl(path)
        return self._probe_text(path)

    def _probe_json_array(self, path: Path) -> str:
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, list) and data and self._is_json_record(data[0]):
                return "json"
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
        return "text"

    def _probe_jsonl(self, path: Path) -> str:
        try:
            with open(path, encoding="utf-8") as fh:
                lines = [ln for ln in fh.read().splitlines() if ln.strip()]
            if not lines:
                return "text"
            valid = sum(1 for ln in lines if self._is_json_record(self._parse_json_line(ln)))
            if valid == len(lines):
                return "jsonl"
        except (json.JSONDecodeError, UnicodeDecodeError, UnicodeError):
            pass
        return "text"

    def _probe_text(self, path: Path) -> str:
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read(20000)
        except (UnicodeDecodeError, OSError):
            return "text"

        if self._is_python_stack(text):
            return "python"
        if self._is_node_stack(text):
            return "node"

        lines = text.splitlines()
        json_lines = 0
        text_lines = 0
        for ln in lines:
            stripped = ln.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith(("{", "[")) and self._is_json_record(self._parse_json_line(stripped)):
                json_lines += 1
            else:
                text_lines += 1
        if json_lines >= TEXT_LINE_MATCH * text_lines:
            return "jsonl"
        return "text"

    @staticmethod
    def _is_python_stack(text: str) -> bool:
        return any(m in text for m in FormatDetector.PYTHON_STACK_MARKERS)

    @staticmethod
    def _is_node_stack(text: str) -> bool:
        if "at " not in text:
            return False
        for marker in FormatDetector.NODE_STACK_MARKERS:
            if marker in text:
                return True
        return False

    @staticmethod
    def _parse_json_line(line: str):
        try:
            return json.loads(line)
        except (json.JSONDecodeError, ValueError):
            return None

    @staticmethod
    def _is_json_record(obj) -> bool:
        if not isinstance(obj, dict):
            return False
        keys = {k.lower() for k in obj.keys()}
        if not keys:
            return False
        score = sum(1 for k in keys if k in {
            "timestamp", "level", "message", "service", "request_id",
            "trace_id", "exception_type", "stack_trace", "msg", "event"})
        return score >= 2
