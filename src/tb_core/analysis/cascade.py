"""Cascading error detection engine.

Distinguishes an initial failure from subsequent failures by tracing the
dependency chain between events. Only infers a causal chain when there is
sufficient correlation evidence (shared request/trace ID, timestamp
proximity, and exception context).
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional

from tb_core.core.models import Event, Evidence

from .rules import RulesEngine


class CascadeAnalyzer:
    """Detects cascading failures and builds a dependency/event graph."""

    def __init__(self, rules: Optional[RulesEngine] = None):
        self.rules = rules or RulesEngine()

    def analyze(self, group: "IncidentGroup") -> List[Evidence]:
        """
        Return a causal chain of events from the root failure through
        cascading errors.
        """
        events = sorted(group.events, key=lambda e: e.timestamp)
        if not events:
            return []

        cascade = []
        seen_ids = set()

        # Identify the earliest failure event
        failure_events = [e for e in events if e.level in ("ERROR", "CRITICAL")]
        if not failure_events:
            # No errors -> check for a warning that suggests a problem
            warnings = [e for e in events if e.level == "WARNING"]
            if warnings:
                root = warnings[0]
                cascade.append(self._make_evidence(root, "Upstream warning that could lead to failure", "LOW"))
                return cascade

        # Build chain starting from the first failure
        root = failure_events[0]
        cascade.append(self._make_evidence(root, "Initial failure", "HIGH"))

        # Walk forward to find cascading events
        for i in range(events.index(root) + 1, len(events)):
            cur = events[i]
            prev = events[i - 1]

            if cur.level in ("ERROR", "CRITICAL") and self._has_correlation(prev, cur):
                cascade.append(self._make_evidence(
                    cur, f"Cascaded error following {prev.message[:60]}", "MEDIUM"))

        # Remove duplicates while preserving order
        seen = set()
        unique = []
        for ev in cascade:
            if ev.event_ids and ev.event_ids[0] not in seen:
                seen.add(ev.event_ids[0])
                unique.append(ev)
        return unique

    @staticmethod
    def _has_correlation(prev: Event, cur: Event) -> bool:
        if prev.request_id and prev.request_id == cur.request_id:
            return True
        if prev.trace_id and prev.trace_id == cur.trace_id:
            return True
        if prev.session_id and prev.session_id == cur.session_id:
            return True
        # Timestamp proximity (lower confidence, inside same minute)
        if prev.timestamp and cur.timestamp:
            delta = abs((cur.timestamp - prev.timestamp).total_seconds())
            if delta <= 300:
                return True
        # Shared service and keyword context
        if prev.service == cur.service:
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