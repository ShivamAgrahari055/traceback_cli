"""Abstract base class for LLM providers.

All providers implement:
- analyze_incident: Generate a structured root-cause analysis from
  deterministic evidence.
- answer_question: Answer an incident-specific question with citations.

Providers are isolated from the analysis engine. New providers can be
added without changing the engine or the CLI.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from tb_core.ai.config import AIConfig
from tb_core.ai.models import LLMAnswer, LLMRootCauseAnalysis, ProviderError
from tb_core.core.models import Event, Evidence


class BaseLLMProvider:
    """Abstract base for LLM providers."""

    def __init__(self, config: AIConfig):
        self.config = config

    def analyze_incident(
        self,
        *,
        incident_id: str,
        title: str,
        severity: str,
        events: List[Event],
        deterministic_analysis: Dict[str, Any],
        redacted_events: List[Event],
    ) -> LLMRootCauseAnalysis:
        """Generate an LLM-enhanced root-cause analysis.

        Args:
            incident_id: The incident identifier.
            title: Incident title.
            severity: Incident severity.
            events: All events in the incident (redacted).
            deterministic_analysis: Output from the deterministic engine.
            redacted_events: Events with secrets already redacted.

        Returns:
            A validated LLMRootCauseAnalysis.
        """
        raise NotImplementedError

    def answer_question(
        self,
        *,
        incident_id: str,
        question: str,
        events: List[Event],
        deterministic_analysis: Dict[str, Any],
        conversation_history: Optional[List[Dict[str, str]]] = None,
    ) -> LLMAnswer:
        """Answer a question about an incident.

        Args:
            incident_id: The incident identifier.
            question: The user's question.
            events: All events in the incident (redacted).
            deterministic_analysis: Output from the deterministic engine.
            conversation_history: Prior Q&A turns for context.

        Returns:
            A validated LLMAnswer.
        """
        raise NotImplementedError

    def _build_evidence_context(
        self,
        events: List[Event],
        deterministic_analysis: Dict[str, Any],
    ) -> str:
        """Build a concise, redacted context string for the LLM.

        Only event metadata (IDs, timestamps, levels, services, messages,
        request/trace IDs) is included. No raw stack traces with secrets.
        """
        lines: List[str] = []
        lines.append(f"Incident ID: {incident_id if hasattr(self, '_last_incident_id') else 'unknown'}")
        lines.append(f"Total events: {len(events)}")
        lines.append("")

        # Group by service
        by_service: Dict[str, List[Event]] = {}
        for ev in events:
            key = ev.service or "unknown"
            by_service.setdefault(key, []).append(ev)

        for svc in sorted(by_service):
            lines.append(f"Service: {svc} ({len(by_service[svc])} events)")
            for ev in by_service[svc][:10]:  # Limit per service
                ts = ev.timestamp.isoformat() if ev.timestamp else "?"
                rid = f" req={ev.request_id}" if ev.request_id else ""
                tid = f" trace={ev.trace_id}" if ev.trace_id else ""
                exc = f" [{ev.exception_type}]" if ev.exception_type else ""
                lines.append(
                    f"  [{ts}] {ev.level} | {ev.event_id}{rid}{tid}{exc} | {ev.message[:200]}"
                )
            if len(by_service[svc]) > 10:
                lines.append(f"  ... and {len(by_service[svc]) - 10} more events")
            lines.append("")

        # Deterministic findings
        lines.append("Deterministic findings:")
        lines.append(f"  Primary error: {deterministic_analysis.get('primary_error', 'None')}")
        rch = deterministic_analysis.get("root_cause_hypothesis")
        if rch:
            lines.append(f"  Root cause hypothesis: {getattr(rch, 'message', str(rch))[:200]}")
        lines.append(f"  Confidence: {deterministic_analysis.get('confidence', 'LOW')}")
        lines.append(f"  Confidence explanation: {deterministic_analysis.get('confidence_explanation', 'N/A')}")

        supporting = deterministic_analysis.get("supporting_evidence", [])
        if supporting:
            lines.append("  Supporting evidence:")
            for ev in supporting[:5]:
                lines.append(f"    - {getattr(ev, 'finding', str(ev))[:200]}")

        downstream = deterministic_analysis.get("downstream_failures", [])
        if downstream:
            lines.append("  Downstream failures:")
            for ev in downstream[:5]:
                lines.append(f"    - {getattr(ev, 'finding', str(ev))[:200]}")

        user_impact = deterministic_analysis.get("user_facing_impact", [])
        if user_impact:
            lines.append("  User-facing impact:")
            for ev in user_impact[:5]:
                lines.append(f"    - {getattr(ev, 'finding', str(ev))[:200]}")

        return "\n".join(lines)

    def _validate_event_references(
        self,
        references: List[EventReference],
        event_ids: set,
    ) -> List[EventReference]:
        """Filter out references to events that don't exist in the incident."""
        valid = []
        for ref in references:
            if ref.event_id in event_ids:
                valid.append(ref)
        return valid
