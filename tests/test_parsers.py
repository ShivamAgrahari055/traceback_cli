"""Tests for the various log parsers (JSON, JSONL, Node, Python)."""

import sys
import json
import pytest

sys.path.insert(0, "c:/traceback-cli/src")

from tb_core.ingestion.text_parser import TextParser
from tb_core.ingestion.json_parser import JsonParser
from tb_core.ingestion.jsonl_parser import JsonlParser
from tb_core.ingestion.node_parser import NodeParser
from tb_core.ingestion.python_parser import PythonParser

text_parser = TextParser()
json_parser = JsonParser()
jsonl_parser = JsonlParser()
node_parser = NodeParser()
python_parser = PythonParser()


# ----------------------------------------------------------------------
# TextParser
# ----------------------------------------------------------------------
def test_text_parser_valid_line():
    event = text_parser.parse_line(
        "2023-10-27 10:30:01 INFO Server started",
        source_file="app.log",
    )
    assert event is not None
    assert event.level == "INFO"
    assert event.message == "Server started"


def test_text_parser_invalid():
    event = text_parser.parse_line("no date here", source_file="app.log")
    assert event is None


def test_text_parser_empty_line():
    assert text_parser.parse_line("", source_file="app.log") is None


# ----------------------------------------------------------------------
# JsonParser
# ----------------------------------------------------------------------
def test_json_parser_array():
    data = [
        {"timestamp": "2023-10-27 10:30:01", "level": "INFO", "message": "start"},
        {"timestamp": "2023-10-27 10:30:02", "level": "ERROR", "message": "fail"},
    ]
    events = json_parser.parse(data, source_file="app.json")
    assert len(events) == 2
    assert events[0].level == "INFO"
    assert events[1].level == "ERROR"
    assert events[0].source_file == "app.json"


def test_json_parser_object():
    data = {
        "timestamp": "2023-10-27 10:30:01",
        "level": "INFO",
        "message": "single",
    }
    events = json_parser.parse(data, source_file="app.json")
    assert len(events) == 1
    assert events[0].message == "single"


def test_json_parser_invalid():
    events = json_parser.parse([{"bogus": "data"}], source_file="app.json")
    assert len(events) == 0


# ----------------------------------------------------------------------
# JsonlParser
# ----------------------------------------------------------------------
def test_jsonl_parser(tmp_path):
    p = tmp_path / "app.jsonl"
    lines = [
        json.dumps({"timestamp": "2023-10-27 10:30:01", "level": "INFO", "message": "start"}),
        json.dumps({"timestamp": "2023-10-27 10:30:02", "level": "ERROR", "message": "fail"}),
    ]
    p.write_text("\n".join(lines), encoding="utf-8")
    events = jsonl_parser.parse_file(str(p))
    assert len(events) == 2
    assert events[0].level == "INFO"
    assert events[1].level == "ERROR"
    assert events[0].line_number == 1
    assert events[1].line_number == 2


def test_jsonl_parser_skips_malformed(tmp_path):
    p = tmp_path / "app.jsonl"
    p.write_text(
        '{"timestamp": "2023-10-27 10:30:01", "level": "INFO", "message": "ok"}\n'
        "not json at all\n"
        '{"timestamp": "2023-10-27 10:30:03", "level": "ERROR", "message": "err"}\n',
        encoding="utf-8",
    )
    events = jsonl_parser.parse_file(str(p))
    assert len(events) == 2
    assert events[0].level == "INFO"
    assert events[1].level == "ERROR"


# ----------------------------------------------------------------------
# NodeParser
# ----------------------------------------------------------------------
def test_node_parser_stack_frame():
    lines = [
        "TypeError: Cannot read properties of null\n",
        "    at /api/login (app.js:12:3)\n",
    ]
    events = node_parser.parse(lines, source_file="app.js")
    assert len(events) == 1
    assert events[0].exception_type == "Error"
    assert "app.js:12" in events[0].stack_trace


def test_node_parser_no_stack():
    events = node_parser.parse(["some random text"], source_file="app.js")
    assert len(events) == 0


# ----------------------------------------------------------------------
# PythonParser
# ----------------------------------------------------------------------
def test_python_parser_stack_trace():
    lines = [
        "Traceback (most recent call last):\n",
        '  File "app.py", line 10, in main\n',
        "TypeError: Cannot read property\n",
    ]
    events = python_parser.parse(lines, source_file="app.py")
    assert len(events) >= 1
    assert events[0].exception_type == "TypeError"
    assert "app.py" in events[0].stack_trace


def test_python_parser_empty():
    events = python_parser.parse([], source_file="app.py")
    assert len(events) == 0
