"""Pydantic models for structured LLM outputs.

Every LLM response is validated against these models before being stored
or displayed. Validation ensures:
- Referenced event IDs actually exist in the incident.
- No hallucinated events or services.
- Confidence is one of HIGH / MEDIUM / LOW.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field, field_validator


class EventReference(BaseModel):
    """A reference to a specific event in the incident."""

    event_id: str
    finding: str
    confidence: str = Field(default="MEDIUM", pattern="^(HIGH|MEDIUM|LOW)$")
    is_observed: bool = True

    @field_validator("confidence", mode="before")
    @classmethod
    def _validate_confidence(cls, v: str) -> str:
        return v.upper()


class CausalChain(BaseModel):
    """A validated causal chain element."""

    event_id: str
    description: str
    category: str = Field(
        default="downstream",
        pattern="^(root_cause|supporting_evidence|application_exception|downstream_failure|user_facing_impact)$",
    )


class LLMRootCauseAnalysis(BaseModel):
    """Validated root-cause analysis from the LLM."""

    summary: str = Field(default="", max_length=2000)
    root_cause_hypothesis: str = Field(default="", max_length=1000)
    confidence: str = Field(default="LOW", pattern="^(HIGH|MEDIUM|LOW)$")
    confidence_explanation: str = Field(default="", max_length=1000)
    affected_services: List[str] = Field(default_factory=list)
    causal_chain: List[CausalChain] = Field(default_factory=list)
    downstream_failures: List[EventReference] = Field(default_factory=list)
    user_facing_impact: List[EventReference] = Field(default_factory=list)
    debugging_recommendations: List[str] = Field(default_factory=list, max_length=10)
    missing_evidence: List[str] = Field(default_factory=list, max_length=5)
    limitations: List[str] = Field(default_factory=list, max_length=5)
    is_llm_generated: bool = True

    @field_validator("confidence", mode="before")
    @classmethod
    def _validate_confidence(cls, v: str) -> str:
        return v.upper()

    @field_validator("affected_services")
    @classmethod
    def _validate_services(cls, v: List[str]) -> List[str]:
        return [s.strip() for s in v if s.strip()]


class LLMAnswer(BaseModel):
    """Validated answer to an incident-specific question."""

    answer: str = Field(default="", max_length=3000)
    confidence: str = Field(default="LOW", pattern="^(HIGH|MEDIUM|LOW)$")
    event_references: List[EventReference] = Field(default_factory=list)
    missing_information: List[str] = Field(default_factory=list, max_length=5)
    is_llm_generated: bool = True

    @field_validator("confidence", mode="before")
    @classmethod
    def _validate_confidence(cls, v: str) -> str:
        return v.upper()


class ProviderError(Exception):
    """Raised when the LLM provider fails."""

    def __init__(self, message: str, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable
