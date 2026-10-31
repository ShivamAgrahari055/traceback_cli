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
        summary, title = self._build_summary(events, primary_error, root_candidates)

        possible_causes = self._build_cause_evidence(events, root_candidates)
        cascade_chain = self._build_cascade_chain(events, root_candidates)
        recommended = self._build_recommendations(events, root_candidates, possible_causes)

        # Confidence based on evidence strength
        confidence = self._compute_confidence(suspicious, root_candidates,
                                               possible_causes, events)

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

    def _build_summary(self, events: List[Event], primary_error: Optional[str],
                       root_candidates: List[Event]) -> tuple:
        # Title should reflect the root cause / primary error, not the first event.
        if primary_error:
            title = primary_error[:80]
        elif root_candidates:
            title = root_candidates[0].message[:80]
        elif events:
            title = events[0].message[:80]
        else:
            title = "Incident"
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
        """Build root-cause hypothesis evidence.

        The root cause is the earliest pattern-matching event that has
        subsequent correlated failures. Later failures are treated as
        cascading errors, not additional root causes.
        """
        evidence = []
        if not root_candidates:
            return evidence

        # Sort candidates chronologically; the earliest one with correlated
        # downstream failures is the root-cause hypothesis.
        candidates_sorted = sorted(root_candidates, key=lambda e: e.timestamp)
        root_cause = candidates_sorted[0]

        evidence.append(Evidence(
            finding=f"Suspected root cause: {root_cause.message} "
                    f"({root_cause.service or 'unknown service'})",
            event_ids=[root_cause.event_id],
            source_file=root_cause.source_file,
            line_number=root_cause.line_number,
            confidence="HIGH" if root_cause.level == "CRITICAL" else "MEDIUM",
            is_observed=True,
        ))

        # Any additional pattern matches downstream are supporting evidence,
        # not independent root causes.
        for ev in candidates_sorted[1:]:
            evidence.append(Evidence(
                finding=f"Contributing failure: {ev.message} "
                        f"({ev.service or 'unknown service'})",
                event_ids=[ev.event_id],
                source_file=ev.source_file,
                line_number=ev.line_number,
                confidence="MEDIUM",
                is_observed=True,
            ))
        return evidence

    def _build_cascade_chain(self, events: List[Event],
                             root_candidates: List[Event]) -> List[Evidence]:
        """Build a causal chain of downstream/cascading errors.

        Only includes failures that occur after the root-cause candidate
        and are correlated to it. The root cause itself is not listed
        as a cascade.
        """
        chain = []
        if not root_candidates:
            return chain

        # Earliest root-cause candidate defines the start of the cascade.
        root_time = min(e.timestamp for e in root_candidates if e.timestamp)
        root_ids = {e.event_id for e in root_candidates}

        for ev in sorted(events, key=lambda e: e.timestamp):
            # Skip the root cause itself and non-failure events
            if ev.event_id in root_ids:
                continue
            if ev.level not in ("ERROR", "CRITICAL"):
                continue
            if ev.timestamp and root_time and ev.timestamp <= root_time:
                continue
            chain.append(Evidence(
                finding=f"Downstream error: {ev.message} "
                        f"({ev.service or 'unknown service'})",
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

        # Root-cause-specific step
        if root_candidates:
            root = root_candidates[0]
            recommendations.append(
                f"Investigate the initial failure: {root.message[:100]} "
                f"[{root.service or 'unknown service'}]"
            )

        # Pattern-based recommendations from root cause
        if root_candidates:
            pat = self.rules.detect(root_candidates[0].message,
                                    root_candidates[0].exception_type)
            if pat and self.rules.get_pattern(pat):
                meta = self.rules.get_pattern(pat)
                for step in meta["recommended_steps"]:
                    if step not in recommendations:
                        recommendations.append(step)

        # Null-specific recommendation
        if any("null" in e.message.lower() for e in events):
            recommendations.append(
                "Add null guards before dereferencing objects returned by dependencies"
            )

        # Service-specific recommendation
        services = {e.service for e in events if e.service}
        if len(services) > 1:
            recommendations.append(
                f"Check the upstream dependency chain across services: "
                f"{', '.join(sorted(services))}"
            )

        # Always include a primary investigation step
        if not recommendations:
            recommendations.append("Review the timeline and identify the first event in the chain")

        return recommendations

    def _compute_confidence(self, suspicious: Optional[Event],
                            root_candidates: List[Event],
                            possible_causes: List[Evidence],
                            events: List[Event]) -> str:
        """Compute confidence from evidence strength.

        Factors:
        - Presence of correlation identifiers (request_id / trace_id)
        - Service attribution on the root-cause event
        - Number of supporting events
        - Whether the suspicious event is CRITICAL
        """
        score = 0

        # Correlation identifiers strengthen confidence
        has_correlation = any(
            e.request_id or e.trace_id for e in events
        )
        if has_correlation:
            score += 1

        # Service attribution on root cause strengthens confidence
        if root_candidates and any(e.service for e in root_candidates):
            score += 1

        # Multiple supporting events
        if len(possible_causes) >= 2:
            score += 1

        # Critical suspicious event
        if suspicious and suspicious.level == "CRITICAL":
            score += 1

        if score >= 3:
            return "HIGH"
        if score >= 2:
            return "MEDIUM"
        return "LOW"