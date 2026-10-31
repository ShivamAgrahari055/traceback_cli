"""Tests for the TextParser."""

import sys
import pytest

sys.path.insert(0, "c:/traceback-cli/src")

from tb_core.ingestion.text_parser import TextParser

parser = TextParser()


def test_parse_valid_log_line():
    """A standard log line should parse into an Event with all fields."""
    line = "2023-10-27 10:30:01 INFO [REQ-101] Server started"
    event = parser.parse_line(line, source_file="c:/traceback-cli/examples/nodejs_error.log")

    assert event is not None
    assert event.event_id is not None
    assert event.timestamp is not None
    assert event.timestamp.hour == 10
    assert event.timestamp.minute == 30
    assert event.level == "INFO"
    assert event.message == "Server started"
    assert event.service is None
    assert event.source_file == "nodejs_error.log"


def test_parse_level_lowercase():
    """Log levels should be normalised to uppercase."""
    line = "2023-10-27 10:30:01 warning [REQ-101] Low priority"
    event = parser.parse_line(line, source_file="test.log")
    assert event is not None
    assert event.level == "WARNING"


def test_parse_invalid_timestamp():
    """An unparseable timestamp should return None."""
    line = "not-a-date INFO something happened"
    assert parser.parse_line(line, source_file="test.log") is None


def test_parse_missing_level():
    """A line without a log level should return None."""
    line = "2023-10-27 10:30:01 some message"
    assert parser.parse_line(line, source_file="test.log") is None


def test_parse_empty_line():
    """Empty lines should return None."""
    assert parser.parse_line("", source_file="test.log") is None
    assert parser.parse_line("   ", source_file="test.log") is None


def test_parse_comment_line():
    """Comment lines (starting with #) should return None."""
    assert parser.parse_line("# this is a comment", source_file="test.log") is None


def test_parse_random_text():
    """Non-matching text should return None."""
    assert parser.parse_line("This is just random text", source_file="test.log") is None


def test_parse_event_id_generated():
    """An event_id should be generated automatically."""
    line = "2023-10-27 10:30:01 INFO message"
    event = parser.parse_line(line, source_file="test.log")
    assert event.event_id is not None
    assert len(event.event_id) == 16  # sha1 truncated to 16 hex chars


def test_event_id_unique_per_file():
    """Same line in different files should produce different event_ids."""
    line = "2023-10-27 10:30:01 INFO msg"
    id1 = parser.parse_line(line, source_file="a.log").event_id
    id2 = parser.parse_line(line, source_file="b.log").event_id
    assert id1 != id2
