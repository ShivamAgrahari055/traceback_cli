from typing import List, Dict
from tb_core.core.models import Event, Incident

class IncidentCorrelator:
    def correlate(self, events: List[Event]) -> List[Incident]:
        """
        Groups events into incidents based on request_id.
        If no request_id is present, events are grouped into 'untracked'.
        """
        groups: Dict[str, List[Event]] = {}
        
        for event in events:
            # Identify the correlation ID (Request ID, Trace ID, or fallback to untracked)
            rid = event.request_id or event.trace_id or "untracked"
            if rid not in groups:
                groups[rid] = []
            groups[rid].append(event)
        
        incidents = []
        for rid, event_list in groups.items():
            # Crucial: Sort events chronologically to ensure the timeline is a a-ccurate
            sorted_events = sorted(event_list, key=lambda x: x.timestamp)
            
            incident = Incident(
                incident_id=rid,
                events=sorted_events,
                severity="INFO" # Default, will be updated by Analyzer
            )
            incidents.append(incident)
            
        return incidents
