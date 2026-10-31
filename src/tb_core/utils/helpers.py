"""General helper utilities for TraceBack."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def severity_color(severity: str) -> str:
    """Return a Textual-compatible color name for a severity level."""
    return {
        "DEBUG": "grey",
        "INFO": "blue",
        "WARNING": "yellow",
        "ERROR": "red",
        "CRITICAL": "red bold",
    }.get(severity.upper(), "white")


def confidence_color(confidence: str) -> str:
    """Return a color name for a confidence level."""
    return {
        "HIGH": "green",
        "MEDIUM": "yellow",
        "LOW": "grey",
    }.get(confidence.upper(), "white")


def truncate(text: Optional[str], max_len: int = 80) -> str:
    """Truncate a string to max_len with ellipsis."""
    if text is None:
        return ""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def group_by_service(events: List[Any]) -> Dict[str, List[Any]]:
    """Group events by their service name."""
    groups: Dict[str, List[Any]] = {}
    for ev in events:
        key = ev.service or "unknown"
        groups.setdefault(key, []).append(ev)
    return groups


def count_by_level(events: List[Any]) -> Dict[str, int]:
    """Count events by log level."""
    counts: Dict[str, int] = {}
    for ev in events:
        lvl = ev.level
        counts[lvl] = counts.get(lvl, 0) + 1
    return counts


def safe_get(obj: Any, attr: str, default: Any = None) -> Any:
    """Safely get an attribute from an object or dict."""
    if isinstance(obj, dict):
        return obj.get(attr, default)
    return getattr(obj, attr, default)


def make_incident_id(prefix: str = "TB") -> str:
    """Generate a deterministic incident ID."""
    import hashlib
    import time

    raw = f"{prefix}-{time.time_ns()}"
    return hashlib.sha1(raw.encode()).hexdigest()[:12]
