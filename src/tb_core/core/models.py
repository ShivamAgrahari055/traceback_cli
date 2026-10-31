"""Core data models for TraceBack events, incidents and evidence.

Application uses Pydantic v2 for all normalised data structures.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
CONFIDENCE_LEVELS = ("HIGH", "MEDIUM", "LOW")

# Levels that indicate a failure
FAILURE_LEVELS = ("ERROR", "CRITICAL")


class Event(BaseModel):
    """A single normalised log record."""

    event_id: str
    timestamp: Optional[datetime] = None
    level: str = "INFO"
    message: str
    service: Optional[str] = None
    request_id: Optional[str] = None
    trace_id: Optional[str] = None
    session_id: Optional[str] = None
    source_file: Optional[str] = None
    line_number: Optional[int] = None
    exception_type: Optional[str] = None
    stack_trace: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    raw_line: Optional[str] = None

    @field_validator("level")
    @classmethod
    def _normalize_level(cls, value: str) -> str:
        return value.upper() if value else "INFO"

    @field_validator("timestamp")
    @classmethod
    def _ensure_timezone_aware(cls, value: datetime) -> datetime:
        return value


class Evidence(BaseModel):
    """Evidence backing an analysis finding."""

    finding: str
    event_ids: List[str] = Field(default_factory=list)
    source_file: Optional[str] = None
    line_number: Optional[int] = None
    confidence: str = "MEDIUM"
    is_observed: bool = True


class Incident(BaseModel):
    """A group of correlated events forming a single failure story."""

    incident_id: str
    title: str = "Untitled incident"
    severity: str = "INFO"
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    primary_error: Optional[str] = None
    related_events: List[Event] = Field(default_factory=list)
    request_id: Optional[str] = None
    trace_id: Optional[str] = None
    affected_services: List[str] = Field(default_factory=list)
    suspected_failure_points: List[str] = Field(default_factory=list)
    possible_root_causes: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    confidence: str = "LOW"
    evidence: List[Evidence] = Field(default_factory=list)
    analysis_metadata: Dict[str, Any] = Field(default_factory=dict)
    request_chains: List[str] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    """Deterministic root-cause / cascade analysis result."""

    title: str
    summary: str
    primary_error: Optional[str] = None
    suspicious_event: Optional[Event] = None
    possible_causes: List[Evidence] = Field(default_factory=list)
    cascade_chain: List[Evidence] = Field(default_factory=list)
    recommended_steps: List[str] = Field(default_factory=list)
    confidence: str = "MEDIUM"
    analysis_metadata: Dict[str, Any] = Field(default_factory=dict)


class IncidentGroup(BaseModel):
    """A collection of incidents that belong to one failure story."""

    title: str
    events: List[Event] = Field(default_factory=list)
    incidents: List[Incident] = Field(default_factory=list)
    analysis: Dict[str, Any] = Field(default_factory=dict)
    evidence: List[Evidence] = Field(default_factory=list)

    def best_severity(self, severity_order: Optional[Dict[str, int]] = None) -> str:
        """Return the highest-severity level present in the group."""
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

    @property
    def start_time(self) -> Optional[datetime]:
        if not self.events:
            return None
        return min(ev.timestamp for ev in self.events)

    @property
    def end_time(self) -> Optional[datetime]:
        if not self.events:
            return None
        return max(ev.timestamp for ev in self.events)