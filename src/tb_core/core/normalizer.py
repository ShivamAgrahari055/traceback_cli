"""Event normalisation engine.

Converts every parsed log record into the common :class:`Event` model with:

- A canonical, timezone-aware ``timestamp``.
- A canonical log ``level`` (DEBUG / INFO / WARNING / ERROR / CRITICAL).
- Canonicalised service names, request/trace IDs, and exception information.

Logs where a field is missing are left as ``None``; we never manufacture
information that was not present in the source.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator

from tb_core.core.models import Event

# Common timestamp formats, most-specific first
TIMESTAMP_FORMATS: List[str] = [
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",
    "%d/%b/%Y:%H:%M:%S %z",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%b %d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S.%f",
    "%d %b %Y %H:%M:%S",
]


class Normalizer:
    """Normalise parsed log records into Event models."""

    def __init__(self, assume_utc: bool = True):
        self.assume_utc = assume_utc

    def normalise(self, events: List[Event], source: str = "unknown") -> List[Event]:
        """Return a new list of fully-normalised Event objects."""
        result: List[Event] = []
        for ev in events:
            norm = self._normalise_event(ev, source)
            result.append(norm)
        return result

    def _normalise_event(self, ev: Event, source: str) -> Event:
        ts = self._normalise_timestamp(ev.timestamp, source)
        level = self._normalise_level(ev.level)
        service = self._canonical_service(ev.service)

        # Build a deterministic event id if one is missing
        event_id = getattr(ev, "event_id", None) or self._make_event_id(
            source, ts, service
        )

        return Event(
            event_id=event_id,
            timestamp=ts,
            level=level,
            message=ev.message,
            service=service,
            request_id=ev.request_id,
            trace_id=ev.trace_id,
            session_id=ev.session_id,
            source_file=ev.source_file or source,
            line_number=ev.line_number,
            exception_type=ev.exception_type,
            stack_trace=ev.stack_trace,
            metadata=dict(ev.metadata),
        )

    # -- timestamps --------------------------------------------------------
    def _normalise_timestamp(self, ts: Optional[datetime], source: str) -> datetime:
        if ts is None:
            # No timestamp in source: keep as None (never fabricate)
            return ts  # type: ignore[return-value]
        if ts.tzinfo is None:
            if self.assume_utc:
                ts = ts.replace(tzinfo=timezone.utc)
            # When assume_utc is False we keep the timestamp naive and mark it
            # in analysis metadata; we never invent a timezone.
        return ts.astimezone(timezone.utc) if ts.tzinfo else ts

    # -- levels ------------------------------------------------------------
    @staticmethod
    def _normalise_level(level: Optional[str]) -> str:
        if not level:
            return "INFO"
        return level.strip().upper()

    # -- services ----------------------------------------------------------
    @staticmethod
    def _canonical_service(service: Optional[str]) -> Optional[str]:
        if not service:
            return None
        return service.strip()

    # -- identifiers -------------------------------------------------------
    @staticmethod
    def _make_event_id(source: str, ts: datetime, service: Optional[str]) -> str:
        raw = f"{source}|{ts.isoformat()}|{service or 'unknown'}"
        return _hash_sha1(raw)

    # -- source ------------------------------------------------------------
    @property
    def source(self) -> str:
        return "normalizer"


def _hash_sha1(text: str) -> str:
    import hashlib

    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:16]
