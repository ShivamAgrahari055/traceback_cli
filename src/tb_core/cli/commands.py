import typer
from typing import Optional
from tb_core.ingestion.loader import LogLoader
from tb_core.core.correlator import IncidentCorrelator
from tb_core.analysis.root_cause import RootCauseAnalyzer
from tb_core.reporting.markdown import MarkdownReporter
from tb_core.security.redactor import SecretRedactor
from tb_core.storage.database import IncidentDatabase

app = typer.Typer(help="TraceBack: Runtime Error Reconstruction & Debugging Tool")

@app.command()
def analyse(
    file_path: str = typer.Argument(..., help="Path to the log file to analyse"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Path to save the markdown report")
):
    """Analyse a log file and reconstruct the incident timeline."""
    typer.echo(f"🔍 Analysing {file_path}...")
    
    # Initialize components
    loader = LogLoader()
    correlator = IncidentCorrelator()
    analyzer = RootCauseAnalyzer()
    reporter = MarkdownReporter()
    redactor = SecretRedactor()
    db = IncidentDatabase()

    # Execution Pipeline
    events = loader.load_file(file_path)
    for e in events:
        e.message = redactor.redact(e.message)
    
    incidents = correlator.correlate(events)
    
    for incident in incidents:
        root_cause = analyzer.analyze(incident)
        incident.root_cause = root_cause
        db.save_incident(incident.incident_id, incident.severity, incident.summary, incident.events)
        
        report = reporter.generate(incident, root_cause)
        if output:
            with open(output, "w", encoding="utf-8") as f:
                f.write(report)
            typer.echo(f"✅ Report saved to {output}")
        else:
            typer.echo("\n" + report)

@app.command()
def incidents():
    """List all incidents saved in the local history database."""
    db = IncidentDatabase()
    all_incidents = db.get_all_incidents()
    
    if not all_incidents:
        typer.echo("No incidents found in history.")
        return

    typer.echo(f"{'ID':<20} | {'Timestamp':<20} | {'Severity':<10}")
    typer.echo("-" * 55)
    for inc in all_incidents:
        typer.echo(f"{inc[0]:<20} | {inc[1]:<20} | {inc[2]:<10}")

@app.command()
def show(incident_id: str):
    """Show the full timeline for a specific incident ID."""
    db = IncidentDatabase()
    # In a real app, we'd fetch the JSON from the DB and rebuild the Incident object
    typer.echo(f"Fetching incident {incident_id} from database...")
    # Logic for fetching and displaying would go here

if __name__ == "__main__":
    app()
