from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List

class Event(BaseModel):
    """The basic unit of a log record."""
    timestamp: datetime
    level: str
    message: str
    service: Optional[str] = "main"
    request_id: Optional[str] = None
    trace_id: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None
    exception: Optional[str] = None

class Incident(BaseModel):
    """A group of correlated events forming a single failure story."""
    incident_id: str
    root_cause_event: Optional[Event] = None
    events: List[Event] = []
    severity: str = "INFO"
    root_cause: Optional[Event] = None
    summary: Optional[str] = None
