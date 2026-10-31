"""Optional LLM intelligence layer for TraceBack.

Provides provider-agnostic AI integration for root-cause analysis and
incident questioning. The application is fully functional without
any AI provider configured.
"""

from tb_core.ai.config import AIConfig
from tb_core.ai.manager import ProviderManager
from tb_core.ai.models import (
    LLMAnswer,
    LLMRootCauseAnalysis,
    ProviderError,
)

__all__ = [
    "AIConfig",
    "ProviderManager",
    "LLMAnswer",
    "LLMRootCauseAnalysis",
    "ProviderError",
]
