"""Root-cause analysis engine (deterministic, evidence-based).

Distinguishes OBSERVED FACT from POSSIBLE CAUSE from RECOMMENDED
INVESTIGATION. Every finding is traceable to a source event with a
confidence label (HIGH / MEDIUM / LOW) derived from evidence strength.

Causal categories:
  - root_cause_hypothesis: earliest event that likely initiated the failure chain
  - supporting_evidence: events that support the causal chain (e.g. db returns null)
  - application_exception: the exception thrown by application code
  - downstream_failures: failures propagated from the root cause
  - user_facing_impact: errors visible to the end user
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from tb_core.core.models import Event, Evidence

from .rules import RulesEngine

FAILURE_LEVELS = ("ERROR", "CRITICAL")


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
                "root_cause_hypothesis": None,
                "supporting_evidence": [],
                "application_exception": None,
                "downstream_failures": [],
                "user_facing_impact": [],
                "confidence": "LOW",
                "confidence_explanation": "No events to analyse.",
            }

        # Identify events by category
        suspicious = self._find_suspicious_event(events)
        root_candidates = self._find_root_cause_candidates(events)

        # Primary error = most severe failure message
        primary_error = self._get_primary_error(events)

        # Build causal categories
        root_cause = self._select_root_cause(root_candidates, events)
        supporting = self._build_supporting_evidence(events, root_candidates, root_cause)
        app_exception = self._find_application_exception(events, root_cause)
        downstream = self._build_downstream_failures(events, root_cause)
        user_impact = self._build_user_facing_impact(events, root_cause)

        # Build summary and title
        summary, title = self._build_summary(events, primary_error, root_cause)

        # Combine all evidence for confidence computation
        all_evidence = supporting + downstream + user_impact

        # Confidence based on evidence strength
        confidence, confidence_explanation = self._compute_confidence(
            suspicious, root_cause, all_evidence, events
        )

        return {
            "title": title,
            "summary": summary,
            "primary_error": primary_error,
            "suspicious_event": suspicious,
            "root_cause_hypothesis": root_cause,
            "supporting_evidence": supporting,
            "application_exception": app_exception,
            "downstream_failures": downstream,
            "user_facing_impact": user_impact,
            "confidence": confidence,
            "confidence_explanation": confidence_explanation,
        }

    # ------------------------------------------------------------------
    # Event identification
    # ------------------------------------------------------------------

    def _find_suspicious_event(self, events: List[Event]) -> Optional[Event]:
        """Return the most suspicious event (highest severity failure)."""
        failure = [e for e in events if e.level in FAILURE_LEVELS]
        if not failure:
            return None
        return max(failure, key=lambda e: 1 if e.level == "CRITICAL" else 0)

    def _find_root_cause_candidates(self, events: List[Event]) -> List[Event]:
        """Return events that match known failure patterns."""
        candidates = []
        for ev in events:
            pat = self.rules.detect(ev.message, ev.exception_type)
            if pat:
                candidates.append(ev)
        return candidates

    def _get_primary_error(self, events: List[Event]) -> Optional[str]:
        errors = [e.message for e in events if e.level in FAILURE_LEVELS]
        return errors[0] if errors else None

    def _select_root_cause(
        self, root_candidates: List[Event], events: List[Event]
    ) -> Optional[Event]:
        """Select the root-cause hypothesis from pattern-matching candidates.

        The root cause is the earliest candidate that has downstream
        correlated failures. If no candidate has clear downstream impact,
        return the earliest candidate.
        """
        if not root_candidates:
            return None

        candidates_sorted = sorted(root_candidates, key=lambda e: e.timestamp)

        # Prefer the earliest candidate that has downstream correlated failures
        for candidate in candidates_sorted:
            if self._has_downstream_failures(candidate, events):
                return candidate

        # Fall back to earliest candidate
        return candidates_sorted[0]

    def _has_downstream_failures(self, candidate: Event, events: List[Event]) -> bool:
        """Check if there are failure events after the candidate."""
        if not candidate.timestamp:
            return False
        for ev in events:
            if (
                ev.level in FAILURE_LEVELS
                and ev.timestamp
                and ev.timestamp > candidate.timestamp
            ):
                return True
        return False

    # ------------------------------------------------------------------
    # Causal category builders
    # ------------------------------------------------------------------

    def _build_supporting_evidence(
        self,
        events: List[Event],
        root_candidates: List[Event],
        root_cause: Optional[Event],
    ) -> List[Evidence]:
        """Build supporting evidence for the causal chain.

        These are events that help explain *why* the root cause happened
        (e.g. database returned null, which led to the null reference).
        They are not themselves failures but are necessary context.
        """
        evidence = []
        if not root_cause:
            return evidence

        root_time = root_cause.timestamp
        root_ids = {root_cause.event_id}
        candidate_ids = {e.event_id for e in root_candidates}

        for ev in sorted(events, key=lambda e: e.timestamp):
            # Skip the root cause and other root-cause candidates
            if ev.event_id in root_ids or ev.event_id in candidate_ids:
                continue
            # Skip failures (they go in downstream or user-facing)
            if ev.level in FAILURE_LEVELS:
                continue
            # Must occur before or at the same time as the root cause to be
            # supporting evidence (same-second precision makes ordering ambiguous)
            if root_time and ev.timestamp and ev.timestamp > root_time:
                continue
            # Look for events that describe the condition leading to failure
            # (e.g. "query returned 0 rows", "result: null")
            if self._is_supporting_context(ev):
                evidence.append(Evidence(
                    finding=f"Supporting context: {ev.message} "
                            f"({ev.service or 'unknown service'})",
                    event_ids=[ev.event_id],
                    source_file=ev.source_file,
                    line_number=ev.line_number,
                    confidence="MEDIUM",
                    is_observed=True,
                ))
        return evidence

    @staticmethod
    def _is_supporting_context(ev: Event) -> bool:
        """Check if an event describes a non-failure condition that contributed to the failure."""
        msg = ev.message.lower()
        supporting_keywords = (
            "null", "not found", "missing", "zero rows", "empty",
            "unavailable", "denied", "refused", "timeout",
        )
        return any(kw in msg for kw in supporting_keywords)

    def _find_application_exception(
        self, events: List[Event], root_cause: Optional[Event]
    ) -> Optional[Event]:
        """Find the application exception thrown by application code.

        This is the actual exception event (e.g. NullReferenceException),
        distinct from the root cause (e.g. database returning null).
        """
        if not root_cause:
            return None

        root_time = root_cause.timestamp
        # Look for exception events at or after the root cause
        for ev in sorted(events, key=lambda e: e.timestamp):
            if ev.exception_type and ev.event_id != root_cause.event_id:
                if root_time is None or ev.timestamp >= root_time:
                    return ev
        # If root cause itself has an exception type, it IS the app exception
        if root_cause.exception_type:
            return root_cause
        return None

    def _build_downstream_failures(
        self, events: List[Event], root_cause: Optional[Event]
    ) -> List[Evidence]:
        """Build downstream failures propagated from the root cause.

        Only includes actual failure events (ERROR/CRITICAL) that occur
        after the root cause and are correlated to it.
        """
        chain = []
        if not root_cause:
            return chain

        root_time = root_cause.timestamp
        root_id = root_cause.event_id

        for ev in sorted(events, key=lambda e: e.timestamp):
            if ev.event_id == root_id:
                continue
            if ev.level not in FAILURE_LEVELS:
                continue
            if root_time and ev.timestamp and ev.timestamp <= root_time:
                continue
            # Only include if correlated (same request/trace/session or close in time)
            if not self._is_correlated(root_cause, ev):
                continue
            chain.append(Evidence(
                finding=f"Downstream failure: {ev.message} "
                        f"({ev.service or 'unknown service'})",
                event_ids=[ev.event_id],
                source_file=ev.source_file,
                line_number=ev.line_number,
                confidence="MEDIUM",
                is_observed=True,
            ))
        return chain

    def _build_user_facing_impact(
        self, events: List[Event], root_cause: Optional[Event]
    ) -> List[Evidence]:
        """Build user-facing impact events.

        These are failures visible to the end user (e.g. frontend errors,
        HTTP 500 returned to client).
        """
        impact = []
        if not root_cause:
            return impact

        root_time = root_cause.timestamp
        root_id = root_cause.event_id

        for ev in sorted(events, key=lambda e: e.timestamp):
            if ev.event_id == root_id:
                continue
            if ev.level not in FAILURE_LEVELS:
                continue
            if root_time and ev.timestamp and ev.timestamp <= root_time:
                continue
            # User-facing = frontend/UI errors or errors returned to client
            if not self._is_user_facing(ev):
                continue
            impact.append(Evidence(
                finding=f"User-facing impact: {ev.message} "
                        f"({ev.service or 'unknown service'})",
                event_ids=[ev.event_id],
                source_file=ev.source_file,
                line_number=ev.line_number,
                confidence="MEDIUM",
                is_observed=True,
            ))
        return impact

    @staticmethod
    def _is_user_facing(ev: Event) -> bool:
        """Check if an event is user-facing (frontend, API gateway, client-facing)."""
        msg = ev.message.lower()
        svc = (ev.service or "").lower()
        user_facing_keywords = (
            "http 500", "login failed", "displayed", "returned to client",
            "frontend", "ui", "browser",
        )
        return any(kw in msg for kw in user_facing_keywords) or svc in ("frontend", "ui", "web")

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

    # ------------------------------------------------------------------
    # Summary and title
    # ------------------------------------------------------------------

    def _build_summary(
        self, events: List[Event], primary_error: Optional[str],
        root_cause: Optional[Event],
    ) -> Tuple[str, str]:
        if root_cause:
            title = root_cause.message[:80]
        elif primary_error:
            title = primary_error[:80]
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

    # ------------------------------------------------------------------
    # Confidence
    # ------------------------------------------------------------------

    def _compute_confidence(
        self,
        suspicious: Optional[Event],
        root_cause: Optional[Event],
        all_evidence: List[Evidence],
        events: List[Event],
    ) -> Tuple[str, str]:
        """Compute confidence from evidence strength.

        Returns (confidence_label, explanation).
        """
        score = 0
        factors: List[str] = []

        # Correlation identifiers strengthen confidence
        has_correlation = any(
            e.request_id or e.trace_id for e in events
        )
        if has_correlation:
            score += 1
            factors.append("events share request/trace identifiers")

        # Service attribution on root cause strengthens confidence
        if root_cause and root_cause.service:
            score += 1
            factors.append("root cause has service attribution")

        # Stack trace on application exception strengthens confidence
        if root_cause and root_cause.stack_trace:
            score += 1
            factors.append("root cause includes stack trace")

        # Supporting evidence (non-failure events that explain the failure)
        if len(all_evidence) >= 2:
            score += 1
            factors.append("multiple supporting events")

        # Timestamp precision reduces confidence when low
        second_precision = all(
            not e.timestamp or e.timestamp.microsecond == 0
            for e in events if e.timestamp
        )
        if second_precision and len(events) > 1:
            score -= 1
            factors.append("timestamps have second-level precision only (ordering ambiguous)")

        # No stack trace reduces confidence
        if root_cause and not root_cause.stack_trace:
            score -= 1
            factors.append("no stack trace available for root cause")

        # Cap score at 0 minimum
        score = max(score, 0)

        if score >= 3:
            label = "HIGH"
        elif score >= 2:
            label = "MEDIUM"
        else:
            label = "LOW"

        explanation = f"Confidence {label}: " + "; ".join(factors) if factors else "Limited evidence."
        return label, explanation
