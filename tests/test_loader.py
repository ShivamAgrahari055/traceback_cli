"""Tests for the LogLoader (streaming ingestion)."""

import sys
import pytest

sys.path.insert(0, "c:/traceback-cli/src")

from tb_core.ingestion.loader import LogLoader


@pytest.fixture
def sample_log_dir(tmp_path):
    d = tmp_path / "logs"
    d.mkdir()
    (d / "api.log").write_text(
        "2023-10-27 10:30:01 INFO Request received\n"
        "2023-10-27 10:30:02 ERROR DB timeout\n",
        encoding="utf-8",
    )
    (d / "web.log").write_text(
        "2023-10-27 10:30:03 INFO GET /health\n",
        encoding="utf-8",
    )
    return str(d)


def test_loader_directory(sample_log_dir):
    loader = LogLoader()
    events = loader.load_dir(sample_log_dir)
    assert len(events) == 3


def test_loader_text_file():
    loader = LogLoader()
    events = loader.load("c:/traceback-cli/examples/nodejs_error.log", fmt="text")
    assert len(events) >= 9


def test_loader_jsonl_file(tmp_path):
    p = tmp_path / "data.jsonl"
    p.write_text(
        '{"timestamp": "2023-10-27 10:30:01", "level": "INFO", "message": "start"}\n'
        '{"timestamp": "2023-10-27 10:30:02", "level": "ERROR", "message": "fail"}\n',
        encoding="utf-8",
    )
    loader = LogLoader()
    events = loader.load(str(p), fmt="jsonl")
    assert len(events) == 2


def test_loader_empty_file(tmp_path):
    p = tmp_path / "empty.log"
    p.write_text("", encoding="utf-8")
    loader = LogLoader()
    events = loader.load(str(p), fmt="text")
    assert len(events) == 0


def test_loader_invalid_lines_ignored(tmp_path):
    p = tmp_path / "mixed.log"
    p.write_text(
        "2023-10-27 10:30:01 INFO valid\n"
        "not a log line\n"
        "2023-10-27 10:30:02 ERROR another valid\n",
        encoding="utf-8",
    )
    loader = LogLoader()
    events = loader.load(str(p), fmt="text")
    assert len(events) == 2
