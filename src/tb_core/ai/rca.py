"""Intelligent root-cause analysis integration.

Combines the deterministic rule-based engine with optional LLM-powered
reasoning. The deterministic engine always runs first and is responsible
for all core analysis. The LLM only enriches the results with causal
explanations, confidence calibration, and debugging recommendations.

If AI is disabled or the provider fails, the deterministic results are
returned unchanged.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from tb_core.ai.config import AIConfig
from tb_core.ai.manager import ProviderManager
from tb_core.ai.models import LLMRootCauseAnalysis
from tb_core.core.models import Event, Incident


def enrich_rca(
    *,
    incident_id: str,
    title: str,
    severity: str,
    events: List[Event],
    deterministic_analysis: Dict[str, Any],
    redacted_events: List[Event],
    ai_enabled: bool = False,
    provider_manager: Optional[ProviderManager] = None,
) -> Dict[str, Any]:
    """Enhance deterministic RCA with LLM reasoning.

    Args:
        incident_id: The incident identifier.
        title: Incident title.
        severity: Incident severity.
        events: All events in the incident.
        deterministic_analysis: Output from RootCauseAnalyzer.analyze().
        redacted_events: Events with secrets already redacted (for sending
            to the LLM).
        ai_enabled: Whether the AI layer is enabled.
        provider_manager: Optional pre-configured provider manager.

    Returns:
        A dict with the same keys as deterministic_analysis, plus
        optional AI-enhanced fields. If AI is disabled or unavailable,
        returns deterministic_analysis unchanged.
    """
    result = dict(deterministic_analysis)

    if not ai_enabled:
        result["ai_enhanced"] = False
        result["ai_source"] = None
        return result

    if provider_manager is None:
        from tb_core.ai.config import AIConfig as _AIConfig

        provider_manager = ProviderManager(_AIConfig())

    llm_result = provider_manager.analyze_incident(
        incident_id=incident_id,
        title=title,
        severity=severity,
        events=events,
        deterministic_analysis=deterministic_analysis,
        redacted_events=redacted_events,
    )

    if llm_result is None:
        result["ai_enhanced"] = False
        result["ai_source"] = None
        return result

    # Merge LLM results into the analysis dict
    result["ai_enhanced"] = True
    result["ai_source"] = "llm"
    result["ai_summary"] = llm_result.summary
    result["ai_root_cause_hypothesis"] = llm_result.root_cause_hypothesis
    result["ai_confidence"] = llm_result.confidence
    result["ai_confidence_explanation"] = llm_result.confidence_explanation
    result["ai_affected_services"] = llm_result.affected_services
    result["ai_causal_chain"] = [
        {
            "event_id": c.event_id,
            "description": c.description,
            "category": c.category,
        }
        for c in llm_result.causal_chain
    ]
    result["ai_downstream_failures"] = [
        {
            "event_id": e.event_id,
            "finding": e.finding,
            "confidence": e.confidence,
            "is_observed": e.is_observed,
        }
        for e in llm_result.downstream_failures
    ]
    result["ai_user_facing_impact"] = [
        {
            "event_id": e.event_id,
            "finding": e.finding,
            "confidence": e.confidence,
            "is_observed": e.is_observed,
        }
        for e in llm_result.user_facing_impact
    ]
    result["ai_debugging_recommendations"] = llm_result.debugging_recommendations
    result["ai_missing_evidence"] = llm_result.missing_evidence
    result["ai_limitations"] = llm_result.limitations

    return result


def get_ai_config() -> AIConfig:
    """Get the AI configuration from environment variables."""
    from tb_core.ai.config import AIConfig

    return AIConfig()


def is_ai_available() -> bool:
    """Check if the AI layer is available (enabled + configured)."""
    from tb_core.ai.manager import ProviderManager

    config = AIConfig()
    manager = ProviderManager(config)
    return manager.is_available
