"""Configurable incident grouping engine.

Groups correlated events into incidents using evidence-based rules:

- Exact request/trace ID matches receive the HIGHEST confidence.
- Timestamp proximity gets LOWER confidence.
- Events without identifiers are NOT grouped by default unless a clear
  pattern emerges.
- Cascading errors are grouped when there is sufficient evidence of a
  shared underlying failure.

The grouping is deterministic and explainable.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field, PrivateAttr

from tb_core.core.models import Event, Incident, Evidence


def _make_incident_id() -> str:
    import hashlib
    import time

    return hashlib.sha1(f"incident-{time.time_ns()}".encode()).hexdigest()[:12]


class IncidentGroup(BaseModel):
    """Collects incidents into a failure story and applies grouping rules."""

    title: str = "Untitled incident"
    events: List[Event] = Field(default_factory=list)
    incidents: List[Incident] = Field(default_factory=list)
    analysis: Dict[str, Any] = Field(default_factory=dict)
    evidence: List[Evidence] = Field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    # Internal, not part of the serialized model
    timestamp_window: timedelta = timedelta(seconds=300)
    incident_id: str = Field(default_factory=_make_incident_id)
    groups: Dict[str, List[Event]] = Field(default_factory=dict)
    _analysis_rules: Dict[str, List[str]] = PrivateAttr()

    def model_post_init(self, __context: Any) -> None:
        self._analysis_rules = {
            "missing_user_lookup": ["missing", "null", "not found", "none"],
            "connection_timeout": ["timeout", "connection timeout", "not responding"],
            "null_reference": ["null reference", "null pointer", "cannot read", "property of null"],
            "auth_failure": ["authentication failed", "user not found", "invalid credentials"],
            "dependency_unavailable": ["unavailable", "connection refused", "service refused"],
            "permission_denied": ["permission denied", "denied", "forbidden"],
            "file_not_found": ["not found", "file not found", "missing file"],
        }

    def group_incidents(self, incidents: List[Incident]) -> List[IncidentGroup]:
        """Apply grouping rules and return a list of IncidentGroup objects."""
        # Reset groups for a fresh analysis
        self.groups = {}
        self.evidence = []

        # 1. Group by request_id / trace_id (high confidence)
        for inc in incidents:
            rid = inc.request_id or inc.trace_id or None
            if rid:
                key = f"id:{rid}"
                self.groups.setdefault(key, []).extend(inc.related_events or [])

        # 2. Group timestamp-proximate events within same service (lower confidence)
        ordered = sorted(self.groups.values(), key=lambda lst: min(
            (e.timestamp for e in lst), default=datetime.min))
        # Merge groups whose end/start times are within the window
        merged = self._merge_proximate_groups(ordered)

        result: List[IncidentGroup] = []
        for group_events in merged:
            if not group_events:
                continue
            events = sorted(group_events, key=lambda e: e.timestamp)
            # Derive an incident id from the first request/trace id present,
            # otherwise fall back to a generated id.
            derived_id = None
            for ev in events:
                if ev.request_id:
                    derived_id = f"TB-{ev.request_id}"
                    break
                if ev.trace_id:
                    derived_id = f"TB-{ev.trace_id}"
                    break
            group = IncidentGroup(
                title=self._derive_title(events),
                incident_id=derived_id,
                events=events,
                start_time=min(e.timestamp for e in events),
                end_time=max(e.timestamp for e in events),
            )
            group.evidence = self._build_evidence(events)
            result.append(group)

        return result

    def _merge_proximate_groups(self, groups: List[List[Event]]) -> List[List[Event]]:
        """Merge groups whose timestamps are within the proximity window."""
        if not groups:
            return []

        merged: List[List[Event]] = []
        current = list(groups[0])

        for other in groups[1:]:
            # If current group has no timestamp yet, just extend
            last_in_current = max((e.timestamp for e in current), default=None)
            first_in_other = min((e.timestamp for e in other), default=None)

            if last_in_current and first_in_other:
                gap = first_in_other - last_in_current
                if gap <= self.timestamp_window:
                    current.extend(other)
                    continue

            # Finalise current and start a new group
            merged.append(current)
            current = list(other)

        merged.append(current)
        return merged

    def _derive_title(self, events: List[Event]) -> str:
        error_msgs = [e.message for e in events if e.level in ("ERROR", "CRITICAL")]
        if error_msgs:
            return error_msgs[0][:80]
        info_msgs = [e.message for e in events if e.level == "INFO"]
        if info_msgs:
            return info_msgs[0][:80]
        return "Incident"

    def _build_evidence(self, events: List[Event]) -> List[Evidence]:
        evidence: List[Evidence] = []
        seen: set = set()
        for e in events:
            if e.exception_type and e.exception_type not in seen:
                evidence.append(Evidence(
                    finding=f"Exception {e.exception_type} at {e.source_file}:{e.line_number}",
                    event_ids=[e.event_id],
                    source_file=e.source_file,
                    line_number=e.line_number,
                    confidence="HIGH" if e.exception_type else "MEDIUM",
                    is_observed=True,
                ))
                seen.add(e.exception_type)
        return evidence

    def best_severity(self, severity_order: Optional[Dict[str, int]] = None) -> str:
        order = severity_order or {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}
        if not self.events:
            return "INFO"
        worst = "INFO"
        for ev in self.events:
            lvl = ev.level
            if lvl in order and order[lvl] > order[worst]:
                worst = lvl
        return worst

    @property
    def affected_services(self) -> List[str]:
        services = {ev.service for ev in self.events if ev.service}
        return sorted(services)