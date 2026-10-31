"""Timeline reconstruction for an incident.

Reconstructs a chronological event sequence, highlighting:

- First suspicious event
- First exception
- Critical failure points
- Cascading errors
- Recovery events

Communicates ambiguity when timestamps have insufficient precision or
ordering is inconsistent.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional, Tuple

from tb_core.core.models import Event, Evidence

TIMELINE_MARKERS = {
    "first_suspicious": "FIRST SUSPICIOUS",
    "first_exception": "FIRST EXCEPTION",
    "critical": "CRITICAL FAILURE",
    "cascade": "CASCADE",
    "recovery": "RECOVERY",
    "normal": "EVENT",
}


class Timeline:
    """Reconstruct and annotate an incident timeline."""

    def build(self, events: List[Event]) -> Dict[str, any]:
        """Return the reconstructed timeline with annotations."""
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        anomalies = self._detect_anomalies(sorted_events)
        first_exception_id = None
        first_suspicious_id = None
        critical_ids = set()
        cascade_ids = set()

        for i, ev in enumerate(sorted_events):
            if ev.level in ("ERROR", "CRITICAL"):
                if first_exception_id is None:
                    first_exception_id = ev.event_id
                if ev.level == "CRITICAL":
                    critical_ids.add(ev.event_id)
                    if first_suspicious_id is None:
                        first_suspicious_id = ev.event_id
            else:
                # Warn on ERROR events that are not exceptions themselves
                if ev.level == "ERROR" and first_suspicious_id is None:
                    first_suspicious_id = ev.event_id

        for i in range(len(sorted_events) - 1):
            cur = sorted_events[i]
            nxt = sorted_events[i + 1]
            if cur.timestamp != nxt.timestamp and cur.timestamp > nxt.timestamp:
                anomalies.append({
                    "type": "timestamp_ordering",
                    "event_index": i,
                    "event_id": cur.event_id,
                    "detail": "Timestamps returned out of chronological order.",
                })

        timeline = [
            {
                "event": ev,
                "marker": self._classify_event(ev, sorted_events, first_exception_id,
                                               first_suspicious_id, critical_ids, cascade_ids),
            }
            for ev in sorted_events
        ]

        return {
            "events": timeline,
            "anomalies": anomalies,
            "first_suspicious": first_suspicious_id,
            "first_exception": first_exception_id,
            "critical_ids": list(critical_ids),
            "cascade_ids": list(cascade_ids),
            "timestamp_precision": self._timestamp_precision(sorted_events),
        }

    def _classify_event(self, ev: Event, all_events: List[Event],
                         first_exception: Optional[str], first_suspicious: Optional[str],
                         critical_ids: set, cascade_ids: set) -> str:
        if ev.event_id == first_exception:
            return TIMELINE_MARKERS["first_exception"]
        if ev.event_id == first_suspicious:
            return TIMELINE_MARKERS["first_suspicious"]
        if ev.event_id in critical_ids:
            return TIMELINE_MARKERS["critical"]
        if ev.level == "INFO" and self._is_recovery(ev, all_events):
            return TIMELINE_MARKERS["recovery"]
        if ev.level == "ERROR" and not ev.exception_type:
            return TIMELINE_MARKERS["cascade"]
        return TIMELINE_MARKERS["normal"]

    @staticmethod
    def _is_recovery(ev: Event, all_events: List[Event]) -> bool:
        recovery_keywords = ("recovered", "reconnected", "success", "healthy", "ok", "completed")
        msg = ev.message.lower()
        return any(k in msg for k in recovery_keywords)

    @staticmethod
    def _detect_anomalies(events: List[Event]) -> List[Dict]:
        anomalies = []
        for i in range(len(events) - 1):
            if events[i].timestamp > events[i + 1].timestamp:
                anomalies.append({
                    "type": "out_of_order",
                    "index": i,
                    "detail": "Event appears out of chronological order."
                })
        return anomalies

    @staticmethod
    def _timestamp_precision(events: List[Event]) -> Optional[str]:
        if not events:
            return None
        import re
        max_precision = 0
        for ev in events[:20]:
            ts = ev.timestamp.isoformat()
            m = re.search(r"\.(\d+)", ts)
            if m:
                max_precision = max(max_precision, len(m.group(1)))
        if max_precision <= 0:
            return "second granularity"
        return f"{max_precision} decimal places"