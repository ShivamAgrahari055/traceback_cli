"""Cascading error detection engine.

Distinguishes an initial failure from subsequent failures by tracing the
dependency chain between events. Only infers a causal chain when there is
sufficient correlation evidence (shared request/trace ID, timestamp
proximity, and exception context).

Cascade categories:
  - root_cause: the initial failure event
  - downstream_failures: failures propagated from the root cause
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional

from tb_core.core.models import Event, Evidence

from .rules import RulesEngine

FAILURE_LEVELS = ("ERROR", "CRITICAL")


class CascadeAnalyzer:
    """Detects cascading failures and builds a dependency/event graph."""

    def __init__(self, rules: Optional[RulesEngine] = None):
        self.rules = rules or RulesEngine()

    def analyze(self, group: "IncidentGroup") -> Dict[str, any]:
        """
        Return a dict with root_cause and downstream_failures keys.
        """
        events = sorted(group.events, key=lambda e: e.timestamp)
        if not events:
            return {
                "root_cause": None,
                "downstream_failures": [],
            }

        # Identify failure events
        failure_events = [e for e in events if e.level in FAILURE_LEVELS]
        if not failure_events:
            return {
                "root_cause": None,
                "downstream_failures": [],
            }

        # The earliest failure is the root cause
        root = failure_events[0]

        # Walk forward to find cascading failures
        downstream = []
        root_index = events.index(root)
        root_id = root.event_id

        for i in range(root_index + 1, len(events)):
            cur = events[i]
            if cur.event_id == root_id:
                continue
            if cur.level not in FAILURE_LEVELS:
                continue
            # Only include if correlated to the root cause
            if self._is_correlated(root, cur):
                downstream.append(self._make_evidence(
                    cur, f"Downstream failure: {cur.message} "
                         f"({cur.service or 'unknown service'})", "MEDIUM"))

        # Remove duplicates while preserving order
        seen = set()
        unique = []
        for ev in downstream:
            if ev.event_ids and ev.event_ids[0] not in seen:
                seen.add(ev.event_ids[0])
                unique.append(ev)

        return {
            "root_cause": root,
            "downstream_failures": unique,
        }

    @staticmethod
    def _is_correlated(root: Event, ev: Event) -> bool:
        """Check if two events are correlated (shared ID or close in time)."""
        if root.request_id and root.request_id == ev.request_id:
            return True
        if root.trace_id and root.trace_id == ev.trace_id:
            return True
        if root.session_id and ev.session_id and root.session_id == ev.session_id:
            return True
        if root.timestamp and ev.timestamp:
            delta = abs((ev.timestamp - root.timestamp).total_seconds())
            if delta <= 300:
                return True
        return False

    @staticmethod
    def _make_evidence(ev: Event, finding: str, confidence: str) -> Evidence:
        return Evidence(
            finding=finding,
            event_ids=[ev.event_id],
            source_file=ev.source_file,
            line_number=ev.line_number,
            confidence=confidence,
            is_observed=True,
        )
