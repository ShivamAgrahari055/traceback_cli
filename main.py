import sys
from tb_core.ingestion.loader import LogLoader
from tb_core.core.correlator import IncidentCorrelator
from tb_core.analysis.root_cause import RootCauseAnalyzer
from tb_core.reporting.markdown import MarkdownReporter
from tb_core.security.redactor import SecretRedactor
from tb_core.storage.database import IncidentDatabase

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <file_path>")
        return

    # Initialize components
    loader = LogLoader()
    correlator = IncidentCorrelator()
    analyzer = RootCauseAnalyzer()
    reporter = MarkdownReporter()
    redactor = SecretRedactor()
    db = IncidentDatabase()

    # 1. Ingestion & Redaction
    print("Loading and redacting logs...")
    raw_events = loader.load_file(sys.argv[1])
    for e in raw_events:
        e.message = redactor.redact(e.message)
    
    # 2. Correlation
    incidents = correlator.correlate(raw_events)
    
    # 3. Analysis & Storage
    for incident in incidents:
        root_cause = analyzer.analyze(incident)
        incident.root_cause = root_cause
        # Save to DB
        db.save_incident(incident.incident_id, incident.severity, incident.summary, incident.events)
        
        # 4. Final Report
        print("\n" + reporter.generate(incident, root_cause))

if __name__ == "__main__":
    main()
