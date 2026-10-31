"""Provider manager — factory and lifecycle for LLM providers.

Reads configuration from environment and instantiates the appropriate
provider. Falls back gracefully when AI is disabled or misconfigured.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from tb_core.ai.config import AIConfig
from tb_core.ai.models import ProviderError
from tb_core.ai.openai_compatible import OpenAICompatibleProvider
from tb_core.core.models import Event


class ProviderManager:
    """Manages LLM provider instantiation and access."""

    _PROVIDERS = {
        "openai_compatible": OpenAICompatibleProvider,
    }

    def __init__(self, config: Optional[AIConfig] = None):
        self.config = config or AIConfig()
        self._provider: Optional[object] = None

    @property
    def is_available(self) -> bool:
        """True if AI is enabled and a provider can be instantiated."""
        if not self.config.enabled:
            return False
        if not self.config.api_key:
            return False
        provider_cls = self._PROVIDERS.get(self.config.provider)
        return provider_cls is not None

    def get_provider(self) -> Optional[object]:
        """Return the configured provider, or None if unavailable."""
        if not self.is_available:
            return None
        if self._provider is None:
            provider_cls = self._PROVIDERS[self.config.provider]
            self._provider = provider_cls(self.config)
        return self._provider

    def analyze_incident(
        self,
        *,
        incident_id: str,
        title: str,
        severity: str,
        events: List[Event],
        deterministic_analysis: Dict[str, Any],
        redacted_events: List[Event],
    ):
        """Run LLM-enhanced analysis, or return None if AI is unavailable.

        Returns an LLMRootCauseAnalysis on success, or None if the AI
        layer is disabled, misconfigured, or the provider fails.
        """
        provider = self.get_provider()
        if provider is None:
            return None
        try:
            return provider.analyze_incident(
                incident_id=incident_id,
                title=title,
                severity=severity,
                events=events,
                deterministic_analysis=deterministic_analysis,
                redacted_events=redacted_events,
            )
        except ProviderError:
            # Provider failures are non-fatal; fall back to deterministic
            return None
        except Exception:
            # Any unexpected error is also non-fatal
            return None

    def answer_question(
        self,
        *,
        incident_id: str,
        question: str,
        events: List[Event],
        deterministic_analysis: Dict[str, Any],
        conversation_history: Optional[List[Dict[str, str]]] = None,
    ):
        """Answer a question, or return None if AI is unavailable."""
        provider = self.get_provider()
        if provider is None:
            return None
        try:
            return provider.answer_question(
                incident_id=incident_id,
                question=question,
                events=events,
                deterministic_analysis=deterministic_analysis,
                conversation_history=conversation_history,
            )
        except ProviderError:
            return None
        except Exception:
            return None

    def config_summary(self) -> dict:
        """Return a safe configuration summary for logging/display."""
        return self.config.redact_for_log()
