from tb_core.core.models import Event, Incident
from typing import Optional

class RootCauseAnalyzer:
    def __init__(self):
        # Define root-cause indicators (errors that usually trigger a crash)
        self.root_indicators = [
            "TypeError", "ValueError", "IndexError", "KeyError", 
            "NullPointerException", "ConnectionTimeout", "PermissionDenied",
            "OutOfMemory", "DatabaseError", "socket.error", "ZeroDivisionError"
        ]
        # Define symptom indicators (errors that are usually results of a root cause)
        self.symptom_indicators = [
            "HTTP 500", "Internal Server Error", "Controller failed", 
            "Connection closed", "Task terminated"
        ]

    def analyze(self, incident: Incident) -> Optional[Event]:
        """
        Implements the Backtracking Logic:
        Walks backward from the final event to find the earliest 'True' error.
        """
        events = incident.events
        if not events:
            return None

        # 1. Walk backward from the end of the timeline
        for event in reversed(events):
            # Check if this event is a "Root Cause" (not just a symptom)
            if self._is_root_cause(event):
                return event
        
        # Fallback: If no specific root cause is found, return the first ERROR event
        for event in events:
            if event.level == "ERROR":
                return event
                
        return None

    def _is_root_cause(self, event: Event) -> bool:
        # An event is a root cause if it contains a root indicator AND NOT a symptom indicator
        msg = event.message.lower()
        
        # Root Cause indicator match
        has_root = any(keyword.lower() in msg for keyword in self.root_indicators)
        # Symptom indicator match
        has_symptom = any(keyword.lower() in msg for keyword in self.symptom_indicators)
        
        return has_root and not has_symptom
