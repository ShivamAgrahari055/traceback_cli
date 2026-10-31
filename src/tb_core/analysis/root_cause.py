"""Root-cause analysis engine (deterministic, evidence-based).

Distinguishes OBSERVED FACT from POSSIBLE CAUSE from RECOMMENDED
INVESTIGATION. Every finding is traceable to a source event with a
confidence label (HIGH / MEDIUM / LOW) derived from evidence strength.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict, List, Optional

from tb_core.core.models import Event, Evidence

from .rules import RulesEngine


class RootCauseAnalyzer:
    """Deterministic root-cause and evidence-based analysis engine."""

    def __init__(self, rules: Optional[RulesEngine] = None):
        self.rules = rules or RulesEngine()

    def analyze(self, group: "IncidentGroup") -> Dict[str, any]:
        events = sorted(group.events, key=lambda e: e.timestamp)
        if not events:
            return {
                "title": "No events",
                "summary": "No events available to analyse.",
                "primary_error": None,
                "suspicious_event": None,
                "possible_causes": [],
                "cascade_chain": [],
                "recommended_steps": ["Provide log events for analysis."],
                "confidence": "LOW",
            }

        # Identify suspicious events and root-cause candidates
        suspicious = self._find_suspicious_events(events)
        root_candidates = self._find_root_cause_candidates(events)

        # Build the primary error and summary
        primary_error = self._get_primary_error(events)
        summary, title = self._build_summary(events, primary_error)

        possible_causes = self._build_cause_evidence(events, root_candidates)
        cascade_chain = self._build_cascade_chain(events)
        recommended = self._build_recommendations(events, root_candidates, possible_causes)

        # Confidence based on evidence strength
        confidence = self._compute_confidence(suspicious, root_candidates, possible_causes)

        return {
            "title": title,
            "summary": summary,
            "primary_error": primary_error,
            "suspicious_event": suspicious,
            "possible_causes": possible_causes,
            "cascade_chain": cascade_chain,
            "recommended_steps": recommended,
            "confidence": confidence,
        }

    def _find_suspicious_events(self, events: List[Event]) -> Optional[Event]:
        """Return the most suspicious event (highest severity)."""
        failure = [e for e in events if e.level in ("ERROR", "CRITICAL")]
        if not failure:
            return None
        return max(failure, key=lambda e: 1 if e.level == "CRITICAL" else 0)

    def _find_root_cause_candidates(self, events: List[Event]) -> List[Event]:
        """Return events that are root-cause candidates based on patterns."""
        from .rules import PATTERNS

        candidates = []
        for ev in events:
            pat = self.rules.detect(ev.message, ev.exception_type)
            if pat and pat in PATTERNS:
                candidates.append((ev, pat))
        return [c[0] for c in candidates]

    def _get_primary_error(self, events: List[Event]) -> Optional[str]:
        errors = [e.message for e in events if e.level in ("ERROR", "CRITICAL")]
        return errors[0] if errors else None

    def _build_summary(self, events: List[Event], primary_error: Optional[str]) -> tuple:
        title = events[0].message[:80] if events else "Incident"
        if primary_error:
            return (
                f"Incident involving: {primary_error}. "
                f"{len(events)} event(s) across "
                f"{len({e.service for e in events if e.service})} service(s).",
                title,
            )
        return (
            f"{len(events)} event(s) across "
            f"{len({e.service for e in events if e.service})} service(s).",
            title,
        )

    def _build_cause_evidence(self, events: List[Event], root_candidates: List[Event]) -> List[Evidence]:
        evidence = []
        for ev in root_candidates:
            evidence.append(Evidence(
                finding=f"Suspected root cause: {ev.message}",
                event_ids=[ev.event_id],
                source_file=ev.source_file,
                line_number=ev.line_number,
                confidence="HIGH" if ev.level == "CRITICAL" else "MEDIUM",
                is_observed=True,
            ))
        return evidence

    def _build_cascade_chain(self, events: List[Event]) -> List[Evidence]:
        """Build a causal chain from the first failure through cascading errors."""
        chain = []
        failure_events = [e for e in events if e.level in ("ERROR", "CRITICAL")]
        for ev in sorted(failure_events, key=lambda e: e.timestamp):
            chain.append(Evidence(
                finding=f"Cascaded error: {ev.message}",
                event_ids=[ev.event_id],
                source_file=ev.source_file,
                line_number=ev.line_number,
                confidence="MEDIUM",
                is_observed=True,
            ))
        return chain

    def _build_recommendations(self, events: List[Event],
                               root_candidates: List[Event],
                               possible_causes: List[Evidence]) -> List[str]:
        recommendations = []
        for ev in root_candidates:
            pat = self.rules.detect(ev.message, ev.exception_type)
            if pat and self.rules.get_pattern(pat):
                meta = self.rules.get_pattern(pat)
                for step in meta["recommended_steps"]:
                    if step not in recommendations:
                        recommendations.append(step)
        if not any("null" in e.message.lower() for e in events) and any(
            "null" in e.message.lower() for e in events
        ):
            recommendations.append("Add null guards before dereferencing objects")
        return recommendations

    def _compute_confidence(self, suspicious: Optional[Event],
                            root_candidates: List[Event],
                            possible_causes: List[Evidence]) -> str:
        if suspicious and suspicious.level == "CRITICAL":
            return "HIGH"
        if possible_causes or root_candidates:
            return "MEDIUM"
        return "LOW"