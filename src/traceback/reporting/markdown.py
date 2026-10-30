from traceback.core.models import Incident

class MarkdownReporter:
    def generate(self, incident: Incident) -> str:
        report = f"# Incident Report: {incident.incident_id}\n\n"
        report += f"**Severity**: {incident.severity}\n"
        report += f"**Summary**: {incident.summary or 'No summary provided'}\n\n"
        
        report += "## Timeline\n"
        for i, event in enumerate(incident.events, 1):
            report += f"{i}. [{event.timestamp}] {event.level}: {event.message}\n"
        
        return report
