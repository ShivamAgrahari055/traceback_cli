"""Timestamp utilities for TraceBack.

Provides helpers for formatting, parsing, and comparing timestamps
in a consistent, timezone-aware manner.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional


def format_timestamp(ts: Optional[datetime], fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Format a datetime for display, returning '--' if None."""
    if ts is None:
        return "--"
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).strftime(fmt)


def format_timestamp_iso(ts: Optional[datetime]) -> Optional[str]:
    """Format a datetime as ISO-8601, returning None if missing."""
    if ts is None:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).isoformat()


def parse_timestamp(value: str) -> Optional[datetime]:
    """Parse a timestamp string into a timezone-aware datetime.

    Tries common formats; returns None if none match.
    """
    from tb_core.core.normalizer import TIMESTAMP_FORMATS

    for fmt in TIMESTAMP_FORMATS:
        try:
            ts = datetime.strptime(value, fmt)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return ts
        except ValueError:
            continue
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts
    except ValueError:
        return None


def now_utc() -> datetime:
    """Return the current UTC time."""
    return datetime.now(timezone.utc)


def age_human(ts: Optional[datetime]) -> str:
    """Return a human-readable age string for a timestamp."""
    if ts is None:
        return "unknown"
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    delta = now_utc() - ts
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return "just now"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"
    days = hours // 24
    return f"{days}d ago"
