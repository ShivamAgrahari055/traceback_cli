from tb_core.core.models import Event, Incident
from typing import Optional

class RootCauseAnalyzer:
    def __init__(self):
        # Define what constitutes a "Root Cause" versus a "Symptom"
        # Root causes are usually specific exceptions or system failures
        self.root_cause_keywords = [
            "TypeError", "ValueError", "IndexError", "KeyError", 
            "NullPointerException", "ConnectionTimeout", "PermissionDenied",
            "OutOfMemory", "DatabaseError", "socket.error"
        ]

    def analyze(self, incident: Incident) -> Optional[Event]:
        """
        Implements the Backtracking Logic:
        Starts from the end of the incident timeline and moves backward
        to find the first 'True' root cause.
        """
        events = incident.events
        if not events:
            return None

        # 1. Start from the end (the crash/symptom) and walk backward
        for event in reversed(events):
            # Check if the message contains any of our root cause keywords
            # or if the exception field is populated.
            is_root = False
            
            # Check the exception field first
            if event.exception:
                is_root = True
            
            # Check the message for root cause keywords
            if not is_root and event.message:
                if any(keyword.lower() in event.message.lower() for keyword in self.root_cause_keywords):
                    is_root = True
            
            # If we found a root cause, return it immediately
            if is_root:
                return event

        # Fallback: If no specific root cause is found, the first error in the timeline 
        # is usually the most likely trigger.
        for event in events:
            if event.level == "ERROR":
                return event
        
        return None
