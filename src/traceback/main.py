import sys
from traceback.ingestion.loader import LogLoader
from traceback.core.correlator import IncidentCorrelator
from traceback.analysis.root_cause import RootCauseAnalyzer
from traceback.reporting.markdown import MarkdownReporter

def main():
    if len(sys.argv) < 2:
        print("Usage: traceback analyse <file_path>")
        return

    # 1. Ingestion
    loader = LogLoader()
    events = loader.load_file(sys.argv[1])
    
    # 2. Correlation
    correlator = IncidentCorrelator()
    incidents = correlator.correlate(events)
    
    # 3. Analysis
    analyzer = RootCauseAnalyzer()
    for incident in incidents:
        analysis = analyzer.analyze(incident)
        incident.root_cause = analysis # Assuming this attribute is added
        
    # 4. Reporting
    reporter = MarkdownReporter()
    for incident in incidents:
        print(reporter.generate(incident))

if __name__ == "__main__":
    main()
