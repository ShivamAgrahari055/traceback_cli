"""Tests for the Normalizer."""

import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, "c:/traceback-cli/src")

from tb_core.core.normalizer import Normalizer

UTC = timezone.utc


def _make_event(**kwargs):
    defaults = {
        "timestamp": datetime.now(timezone.utc),
        "level": "INFO",
        "message": "msg",
        "service": "api",
        "event_id": "test",
        "request_id": None,
        "trace_id": None,
        "session_id": None,
        "source_file": "app.log",
        "line_number": None,
        "exception_type": None,
        "stack_trace": None,
        "metadata": {},
        "raw_line": None,
    }
    defaults.update(kwargs)
    return type("Event", (), defaults)()


def test_normalise_timestamp_naively_assumed_utc():
    """Naive timestamps are assumed to be UTC."""
    normalizer = Normalizer(assume_utc=True)
    ev = _make_event(timestamp=datetime(2023, 10, 27, 10, 30, 1))
    result = normalizer._normalise_timestamp(ev.timestamp, "test.log")
    assert result.tzinfo == UTC


def test_normalise_timestamp_naive_when_utc_disabled():
    """With assume_utc=False, naive timestamps stay naive."""
    normalizer = Normalizer(assume_utc=False)
    ev = _make_event(timestamp=datetime(2023, 10, 27, 10, 30, 1))
    result = normalizer._normalise_timestamp(ev.timestamp, "test.log")
    assert result.tzinfo is None


def test_normalise_level_normalised():
    """Log levels are canonicalised to uppercase."""
    normalizer = Normalizer(assume_utc=True)
    ev = _make_event(level="warning")
    results = normalizer.normalise([ev])
    assert results[0].level == "WARNING"


def test_normalise_service_canonicalised():
    """Service names are trimmed of whitespace."""
    normalizer = Normalizer(assume_utc=True)
    ev = _make_event(service="  api  ")
    results = normalizer.normalise([ev])
    assert results[0].service == "api"


def test_normalise_event_id_generated():
    """Events without event_id get one generated."""
    normalizer = Normalizer(assume_utc=True)
    ev = _make_event(event_id=None)
    results = normalizer.normalise([ev])
    assert results[0].event_id is not None
    assert len(results[0].event_id) == 16


def test_normalise_missing_timestamp_keeps_none():
    """Events without timestamp keep None timestamp."""
    normalizer = Normalizer(assume_utc=True)
    ev = _make_event(timestamp=None)
    results = normalizer.normalise([ev])
    assert results[0].timestamp is None


def test_normalise_path_streams_input():
    """normalise does not mutate the input list in place (returns new list)."""
    normalizer = Normalizer(assume_utc=True)
    evs = [_make_event()]
    original = list(evs)
    results = normalizer.normalise(evs)
    assert results is not evs  # new list
    assert evs == original  # original unchanged
