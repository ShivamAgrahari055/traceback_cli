from traceback.core.models import Incident, Event
from typing import Optional

class MarkdownReporter:
    def generate(self, incident: Incident, root_cause: Optional[Event] = None) -> str:
        report = f"# Incident Report: {incident.incident_id}\n\n"
        report += f"**Severity**: {incident.severity}\n"
        report += f"**Summary**: {incident.summary or 'No summary provided'}\n\n"
        
        if root_cause:
            report += "## 🚩 Root Cause Identified\n"
            report += f"> **{root_cause.level}**: {root_cause.message}\n"
            report += f"Found at: {root_cause.timestamp}\n\n"
        
        report += "## 🕒 Timeline\n"
        for i, event in enumerate(incident.events, 1):
            prefix = "👉 " if event == root_cause else "  "
            report += f"{prefix}{i}. [{event.timestamp}] {event.level}: {event.message}\n"
        
        return report
