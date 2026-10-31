"""Tests for the FormatDetector."""

import sys
import json
import pytest

sys.path.insert(0, "c:/traceback-cli/src")

from tb_core.ingestion.detector import FormatDetector

detector = FormatDetector()


def test_detect_auto_nodejs_log():
    """nodejs_error.log should be detected as 'text'."""
    fmt = detector.detect("c:/traceback-cli/examples/nodejs_error.log", "auto")
    assert fmt == "text"


def test_detect_explicit_format():
    """Explicit format overrides detection."""
    fmt = detector.detect("c:/traceback-cli/examples/nodejs_error.log", "jsonl")
    assert fmt == "jsonl"


def test_detect_unknown_format():
    """An unknown format should raise ValueError."""
    with pytest.raises(ValueError):
        detector.detect("c:/traceback-cli/examples/nodejs_error.log", "bogus")


@pytest.fixture
def sample_jsonl_file(tmp_path):
    p = tmp_path / "sample.jsonl"
    lines = [
        json.dumps({"timestamp": "2023-10-27 10:30:01", "level": "INFO", "message": "start"}),
        json.dumps({"timestamp": "2023-10-27 10:30:02", "level": "ERROR", "message": "fail"}),
    ]
    p.write_text("\n".join(lines), encoding="utf-8")
    return str(p)


def test_detect_jsonl(sample_jsonl_file):
    """JSONL files should be detected as 'jsonl'."""
    fmt = detector.detect(sample_jsonl_file, "auto")
    assert fmt == "jsonl"


@pytest.fixture
def sample_json_array_file(tmp_path):
    p = tmp_path / "sample.json"
    data = [
        {"timestamp": "2023-10-27 10:30:01", "level": "INFO", "message": "start"},
        {"timestamp": "2023-10-27 10:30:02", "level": "ERROR", "message": "fail"},
    ]
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


def test_detect_json_array(sample_json_array_file):
    """JSON array files should be detected as 'json'."""
    fmt = detector.detect(sample_json_array_file, "auto")
    assert fmt == "json"


def test_detect_python_stack_trace(tmp_path):
    """Python stack traces should be detected as 'python'."""
    p = tmp_path / "traceback.log"
    p.write_text(
        "Traceback (most recent call last):\n"
        '  File "app.py", line 10, in main\n'
        "TypeError: Cannot read property\n",
        encoding="utf-8",
    )
    fmt = detector.detect(str(p), "auto")
    assert fmt == "python"


def test_detect_node_stack_trace(tmp_path):
    """Node stack traces should be detected as 'node'."""
    p = tmp_path / "node.log"
    p.write_text(
        "TypeError: Cannot read properties of null\n"
        "    at /api/login (app.js:12:3)\n",
        encoding="utf-8",
    )
    fmt = detector.detect(str(p), "auto")
    assert fmt == "node"


def test_detect_plain_text(tmp_path):
    """Plain text logs without stack markers should be 'text'."""
    p = tmp_path / "plain.log"
    p.write_text("2023-10-27 10:30:01 INFO Server started\n", encoding="utf-8")
    fmt = detector.detect(str(p), "auto")
    assert fmt == "text"
