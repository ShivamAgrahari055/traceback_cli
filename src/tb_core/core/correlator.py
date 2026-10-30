from typing import List, Dict
from tb_core.core.models import Event, Incident

class IncidentCorrelator:
    def correlate(self, events: List[Event]) -> List[Incident]:
        """
        Groups a flat list of events into Incidents based on their request_id.
        """
        groups: Dict[str, List[Event]] = {}
        
        for event in events:
            rid = event.request_id or "untracked"
            if rid not in groups:
                groups[rid] = []
            groups[rid].append(event)
        
        incidents = []
        for rid, event_list in groups.items():
            sorted_events = sorted(event_list, key=lambda x: x.timestamp)
            
            incident = Incident(
                incident_id=rid,
                events=sorted_events,
                severity="INFO"
            )
            incidents.append(incident)
            
        return incidents
