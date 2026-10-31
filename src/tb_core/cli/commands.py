import json
import typer
from datetime import datetime
from typing import Optional, Dict, Any

from tb_core.ingestion.loader import LogLoader
from tb_core.ingestion.detector import FormatDetector
from tb_core.core.normalizer import Normalizer
from tb_core.core.models import Event, Incident
from tb_core.core.correlator import IncidentCorrelator
from tb_core.core.incident import IncidentGroup
from tb_core.core.timeline import Timeline
from tb_core.analysis.root_cause import RootCauseAnalyzer
from tb_core.analysis.cascade import CascadeAnalyzer
from tb_core.analysis.rules import RulesEngine
from tb_core.analysis.recommendations import RecommendationBuilder
from tb_core.security.redactor import SecretRedactor
from tb_core.reporting.markdown import MarkdownReporter
from tb_core.reporting.json_report import JSONReporter
from tb_core.storage.database import IncidentDatabase
from tb_core.ai.config import AIConfig
from tb_core.ai.manager import ProviderManager
from tb_core.ai.rca import enrich_rca, get_ai_config, is_ai_available

app = typer.Typer(
    name="traceback",
    help="TraceBack: Runtime Error Reconstruction & Debugging Tool",
    add_completion=False,
    rich_markup_mode="rich",
)

VERSION = "TraceBack 0.1.0"


def version_callback(value: bool):
    if value:
        typer.echo(VERSION)
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Show the version and exit.",
    ),
):
    pass


def _echo_success(msg: str):
    typer.secho(msg, fg=typer.colors.GREEN)


@app.command("analyse")
def analyse_cmd(
    file_path: str = typer.Argument(..., help="Path to the log file, directory, or source"),
    fmt: str = typer.Option(
        "auto", "--format", "-f", help="Input log format: auto, json, jsonl, text, python, node"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Path to save the markdown report"
    ),
    redact: bool = typer.Option(
        True, "--redact", help="Redact secrets before analysis"
    ),
):
    """Analyse logs and reconstruct the incident timeline."""
    typer.echo(f"[bold]Analysing {file_path}...[/bold]")

    loader = LogLoader()
    detector = FormatDetector()
    resolved_fmt = detector.detect(file_path, fmt)
    typer.echo(f"Detected format: [cyan]{resolved_fmt}[/cyan]")

    events = loader.load(file_path, fmt=resolved_fmt)
    if not events:
        typer.echo("[yellow]No log entries could be parsed.[/yellow]")
        raise typer.Exit(0)

    typer.echo(f"Parsed [green]{len(events)}[/green] events")

    redactor = SecretRedactor()
    if redact:
        for e in events:
            e.message = redactor.redact(e.message)
            if e.stack_trace:
                e.stack_trace = redactor.redact(e.stack_trace)

    normalizer = Normalizer(assume_utc=True)
    normalised = normalizer.normalise(events)

    correlator = IncidentCorrelator()
    incidents = correlator.correlate(normalised)

    group = IncidentGroup()
    grouped = group.group_incidents(incidents)

    rules = RulesEngine()
    analyzer = RootCauseAnalyzer(rules)
    cascade = CascadeAnalyzer()
    rec_builder = RecommendationBuilder()

    db = IncidentDatabase()

    ai_config = get_ai_config()
    ai_manager = ProviderManager(ai_config)

    for g in grouped:
        report = _build_report(g, analyzer, cascade, rec_builder, redactor, output)
        report_incident_id = report["incident"].incident_id

        # Enrich with LLM reasoning if AI is available
        if ai_config.enabled:
            redacted_events = []
            for ev in g.events:
                redacted_events.append(
                    Event(
                        event_id=ev.event_id,
                        timestamp=ev.timestamp,
                        level=ev.level,
                        message=redactor.redact(ev.message) if ev.message else None,
                        service=ev.service,
                        request_id=ev.request_id,
                        trace_id=ev.trace_id,
                        session_id=ev.session_id,
                        source_file=ev.source_file,
                        line_number=ev.line_number,
                        exception_type=ev.exception_type,
                        stack_trace=redactor.redact(ev.stack_trace)
                        if ev.stack_trace else None,
                        metadata=dict(ev.metadata),
                    )
                )
            ai_enriched = enrich_rca(
                incident_id=report_incident_id,
                title=report["title"],
                severity=report["severity"],
                events=g.events,
                deterministic_analysis=report["root_cause"],
                redacted_events=redacted_events,
                ai_enabled=ai_config.enabled,
                provider_manager=ai_manager,
            )
            report["root_cause"] = ai_enriched

        db.save_incident(
            incident_id=report_incident_id,
            title=report["title"],
            severity=report["severity"],
            summary=report["summary"],
            events=report["events"],
            start_time=report["start_time"],
            end_time=report["end_time"],
            primary_error=report["primary_error"],
            affected_services=report["affected_services"],
            confidence=report["confidence"],
            report_path=report["report_path"],
        )
        _echo_success(f"  Saved incident [cyan]{report_incident_id}[/cyan] to history")

        if output:
            _write_report(report, output, report_incident_id)
        else:
            typer.echo(report["markdown"])


def _build_report(
    group, analyzer, cascade, rec_builder, redactor, output: Optional[str] = None
) -> Dict[str, Any]:
    events = group.events
    analysis = group.analysis

    root_cause = analyzer.analyze(group)
    cascade_chain = cascade.analyze(group)
    recommendations = rec_builder.build(group, cascade_chain, root_cause)
    evidence = group.evidence

    severity_order = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}
    severity = group.best_severity(severity_order)

    primary_error = root_cause.get("primary_error") if root_cause else None
    if not primary_error and events:
        primary_error = events[0].message

    affected_services = group.affected_services
    title = analysis.get("title") if analysis else group.title or "Incident"
    summary = analysis.get("summary") if analysis else (
        f"{len(events)} events across {len(affected_services)} service(s) - {severity} severity"
    )

    md_reporter = MarkdownReporter()
    report_dict = {
        "incident": group,
        "title": title,
        "severity": severity,
        "summary": summary,
        "root_cause": root_cause,
        "cascade_chain": cascade_chain,
        "recommendations": recommendations,
        "evidence": evidence,
        "events": events,
        "start_time": group.start_time,
        "end_time": group.end_time,
        "primary_error": primary_error,
        "affected_services": affected_services,
        "confidence": root_cause.get("confidence") if root_cause else "MEDIUM",
        "report_path": output,
    }
    report_dict["markdown"] = md_reporter.generate(report_dict)
    return report_dict


def _write_report(report, output: str, incident_id: str):
    md_reporter = MarkdownReporter()
    md_reporter.write_markdown_report(report, output)


@app.command("incidents")
def incidents_cmd():
    """List all incidents saved in the local history database."""
    db = IncidentDatabase()
    all_incidents = db.get_all_incidents()

    if not all_incidents:
        typer.echo("No incidents found in history.")
        return

    typer.echo(f"Found [green]{len(all_incidents)}[/green] incident(s)\n")
    typer.echo(f"{'ID':<12} | {'Severity':<10} | {'Confidence':<11} | {'Created':<22}")
    typer.echo("-" * 60)
    for inc in all_incidents:
        typer.echo(
            f"{inc['id']:<12} | {inc['severity']:<10} | "
            f"{inc['confidence']:<11} | {inc['created_at'] or '' :<22}"
        )


@app.command("show")
def show_cmd(incident_id: str):
    """Show the full detail for a specific incident."""
    db = IncidentDatabase()
    row = db.get_incident(incident_id)
    if not row:
        typer.echo(f"[red]Incident '{incident_id}' not found in history.[/red]")
        raise typer.Exit(1)

    typer.echo(f"Title:   {row['title']}")
    typer.echo(f"Severity:{row['severity']}")
    typer.echo(f"Created: {row['created_at']}")
    if row["start_time"]:
        typer.echo(f"Start:   {row['start_time']}")
    if row["end_time"]:
        typer.echo(f"End:     {row['end_time']}")
    if row["primary_error"]:
        typer.echo(f"Primary error: {row['primary_error']}")
    if row["summary"]:
        typer.echo(f"Summary: {row['summary']}")
    if row["raw_json"]:
        typer.echo("\n[bold]Full stored JSON:[/bold]")
        typer.echo(row["raw_json"])


@app.command("timeline")
def timeline_cmd(incident_id: str):
    """View the chronological timeline for an incident."""
    db = IncidentDatabase()
    events = db.get_events_for_incident(incident_id)
    if not events:
        typer.echo(f"[red]No events found for incident '{incident_id}'.[/red]")
        raise typer.Exit(1)

    typer.echo(f"Timeline for incident [cyan]{incident_id}[/cyan]\n")
    for ev in events:
        ts = ev["timestamp"] or "?"
        level_style = {"ERROR": "red", "CRITICAL": "red bold", "WARNING": "yellow"}.get(
            ev["level"], "white"
        )
        typer.echo(
            f"  [dim]{ts}[/dim]  "
            f"[{ev['level']}] "
            f"[{ev['service'] or 'unknown'}] "
            f"{ev['message'][:90]}"
        )


@app.command("report")
def report_cmd(
    incident_id: str = typer.Argument(..., help="Incident ID to export"),
    fmt: str = typer.Option("markdown", "--format", "-f", help="Output format: markdown or json"),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Output file path"
    ),
):
    """Generate a Markdown or JSON report for an incident."""
    db = IncidentDatabase()
    row = db.get_incident(incident_id)
    if not row:
        typer.echo(f"[red]Incident '{incident_id}' not found in history.[/red]")
        raise typer.Exit(1)

    events = db.get_events_for_incident(incident_id)
    if not events:
        typer.echo(f"[red]No events found for incident '{incident_id}'.[/red]")
        raise typer.Exit(1)

    # Convert stored event dicts back to Event objects
    event_objs = []
    for ev in events:
        try:
            ts = datetime.fromisoformat(ev["timestamp"]) if ev.get("timestamp") else None
        except ValueError:
            ts = None
        event_objs.append(
            Event(
                event_id=ev.get("event_id", ""),
                timestamp=ts,
                level=ev.get("level", "INFO"),
                message=ev.get("message", ""),
                service=ev.get("service"),
                request_id=ev.get("request_id"),
                trace_id=ev.get("trace_id"),
                session_id=ev.get("session_id"),
                source_file=ev.get("source_file"),
                line_number=ev.get("line_number"),
                exception_type=ev.get("exception_type"),
                stack_trace=ev.get("stack_trace"),
                metadata=ev.get("metadata", {}),
            )
        )

    # Re-run analysis to populate RCA data for the report
    rules_engine = RulesEngine()
    analyzer = RootCauseAnalyzer(rules_engine)
    cascade = CascadeAnalyzer(rules_engine)
    rec_builder = RecommendationBuilder()

    group = IncidentGroup(
        title=row["title"] or "Incident",
        events=event_objs,
    )
    root_cause = analyzer.analyze(group)
    cascade_chain = cascade.analyze(group)
    recommendations = rec_builder.build(group, cascade_chain, root_cause)
    evidence = group.evidence

    report = {
        "incident": Incident(
            incident_id=incident_id,
            title=row["title"] or "Incident",
            severity=row["severity"] or "INFO",
            start_time=datetime.fromisoformat(row["start_time"]) if row["start_time"] else None,
            end_time=datetime.fromisoformat(row["end_time"]) if row["end_time"] else None,
            related_events=event_objs,
            primary_error=row["primary_error"] or "Unknown",
            affected_services=list({e.service for e in event_objs if e.service}),
            confidence=row["confidence"] or "MEDIUM",
        ),
        "title": row["title"] or "Incident",
        "severity": row["severity"],
        "summary": row["summary"] or "No summary available.",
        "primary_error": row["primary_error"] or "Unknown",
        "start_time": row["start_time"],
        "end_time": row["end_time"],
        "events": event_objs,
        "affected_services": list({e.service for e in event_objs if e.service}),
        "confidence": root_cause.get("confidence", row["confidence"] or "MEDIUM"),
        "root_cause": root_cause,
        "cascade_chain": cascade_chain,
        "recommendations": recommendations,
        "evidence": evidence,
        "report_path": row["report_path"],
    }

    if fmt == "markdown":
        reporter = MarkdownReporter()
        report_text = reporter.generate(report)
    elif fmt == "json":
        reporter = JSONReporter()
        report_text = reporter.generate_report(report)
    else:
        typer.echo(f"[red]Unknown format '{fmt}'. Use markdown or json.[/red]")
        raise typer.Exit(1)

    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(report_text)
        typer.echo(f"Report saved to [cyan]{output}[/cyan]")
    else:
        typer.echo(report_text)


@app.command("tui")
def tui_cmd():
    """Launch the interactive Terminal User Interface."""
    try:
        from tb_core.tui.app import TraceBackApp
    except Exception as exc:
        typer.echo(f"[red]Could not start TUI: {exc}[/red]")
        raise typer.Exit(1)
    app_tui = TraceBackApp()
    app_tui.run()


@app.command("ask")
def ask_cmd(
    incident_id: str = typer.Argument(..., help="Incident ID to ask about"),
    question: str = typer.Argument(..., help="Question to ask about the incident"),
):
    """Ask a question about a specific incident (requires AI)."""
    ai_config = get_ai_config()
    if not ai_config.enabled:
        typer.echo(
            "[red]AI is disabled. Set TRACEBACK_AI_ENABLED=true and "
            "TRACEBACK_AI_API_KEY to use this command.[/red]"
        )
        raise typer.Exit(1)

    if not ai_config.api_key:
        typer.echo(
            "[red]No API key configured. Set TRACEBACK_AI_API_KEY.[/red]"
        )
        raise typer.Exit(1)

    db = IncidentDatabase()
    row = db.get_incident(incident_id)
    if not row:
        typer.echo(f"[red]Incident '{incident_id}' not found in history.[/red]")
        raise typer.Exit(1)

    events = db.get_events_for_incident(incident_id)
    if not events:
        typer.echo(f"[red]No events found for incident '{incident_id}'.[/red]")
        raise typer.Exit(1)

    # Convert stored event dicts back to Event objects
    event_objs = []
    for ev in events:
        try:
            ts = datetime.fromisoformat(ev["timestamp"]) if ev.get("timestamp") else None
        except ValueError:
            ts = None
        event_objs.append(
            Event(
                event_id=ev.get("event_id", ""),
                timestamp=ts,
                level=ev.get("level", "INFO"),
                message=ev.get("message", ""),
                service=ev.get("service"),
                request_id=ev.get("request_id"),
                trace_id=ev.get("trace_id"),
                session_id=ev.get("session_id"),
                source_file=ev.get("source_file"),
                line_number=ev.get("line_number"),
                exception_type=ev.get("exception_type"),
                stack_trace=ev.get("stack_trace"),
                metadata=ev.get("metadata", {}),
            )
        )

    # Re-run deterministic analysis
    rules_engine = RulesEngine()
    analyzer = RootCauseAnalyzer(rules_engine)
    cascade = CascadeAnalyzer(rules_engine)
    rec_builder = RecommendationBuilder()

    group = IncidentGroup(
        title=row["title"] or "Incident",
        events=event_objs,
    )
    root_cause = analyzer.analyze(group)
    cascade_chain = cascade.analyze(group)
    recommendations = rec_builder.build(group, cascade_chain, root_cause)

    deterministic_analysis = {
        "title": root_cause.get("title", row["title"] or "Incident"),
        "summary": root_cause.get("summary", ""),
        "primary_error": root_cause.get("primary_error"),
        "root_cause_hypothesis": root_cause.get("root_cause_hypothesis"),
        "supporting_evidence": root_cause.get("supporting_evidence", []),
        "application_exception": root_cause.get("application_exception"),
        "downstream_failures": root_cause.get("downstream_failures", []),
        "user_facing_impact": root_cause.get("user_facing_impact", []),
        "confidence": root_cause.get("confidence", "LOW"),
        "confidence_explanation": root_cause.get("confidence_explanation", ""),
    }

    ai_manager = ProviderManager(ai_config)
    llm_answer = ai_manager.answer_question(
        incident_id=incident_id,
        question=question,
        events=event_objs,
        deterministic_analysis=deterministic_analysis,
    )

    if llm_answer is None:
        typer.echo(
            "[red]AI provider failed to answer. Try again later.[/red]"
        )
        raise typer.Exit(1)

    typer.echo(f"\n[bold]Question:[/bold] {question}")
    typer.echo(f"[bold]Answer:[/bold] {llm_answer.answer}")
    typer.echo(f"[bold]Confidence:[/bold] {llm_answer.confidence}")
    if llm_answer.event_references:
        typer.echo("\n[bold]Evidence:[/bold]")
        for ref in llm_answer.event_references:
            typer.echo(f"  - {ref.finding} (event: {ref.event_id})")
    if llm_answer.missing_information:
        typer.echo("\n[bold]Missing information:[/bold]")
        for item in llm_answer.missing_information:
            typer.echo(f"  - {item}")


def main():
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--version":
        typer.echo(VERSION)
        raise typer.Exit()

    app()


if __name__ == "__main__":
    main()