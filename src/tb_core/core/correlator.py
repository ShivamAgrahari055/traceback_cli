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
            
            # Determine which identifier was used for grouping
            req_id = None
            tr_id = None
            for ev in sorted_events:
                if ev.request_id:
                    req_id = ev.request_id
                    break
                if ev.trace_id:
                    tr_id = ev.trace_id
                    break

            incident = Incident(
                incident_id=rid,
                related_events=sorted_events,
                severity="INFO",
                request_id=req_id,
                trace_id=tr_id,
            )
            incidents.append(incident)
            
        return incidents
