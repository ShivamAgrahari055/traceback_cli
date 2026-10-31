# TraceBack

"From scattered logs to a reconstructed debugging story."

TraceBack is a local-first developer debugging utility that analyses application
logs, correlates related events, reconstructs chronological incident timelines,
and identifies likely failure points.

Developers frequently encounter situations where an application fails, but the
relevant information is scattered across application logs, backend logs, database
logs, API request logs, Python stack traces, Node.js exceptions, and multiple
microservices. TraceBack automates the investigation process.

A developer provides a directory containing logs, executes one command, and
receives:

1. A summary of detected incidents
2. A chronological reconstruction of related events
3. Identification of suspicious events and likely failure points
4. Related stack traces
5. Evidence-backed possible root causes
6. Suggested debugging steps
7. Exportable incident reports

## Core Concept

**Scattered Logs → Correlated Events → Reconstructed Timeline → Evidence-Based Investigation → Actionable Debugging Report**

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.12+ |
| CLI | Typer |
| TUI | Textual |
| Terminal styling | Rich |
| Data validation | Pydantic v2 |
| Database | SQLite |
| Testing | Pytest |
| Packaging | pyproject.toml, uv |

## Installation

### Clone and install

```bash
# Clone the repository
git clone https://github.com/ShivamAgrahari055/tr.git
cd tr

# Install dependencies with uv
uv sync

# Or with pip
pip install -e .
```

### Windows PowerShell PATH setup (required for the `traceback` command)

On Windows, pip installs the `traceback` executable into Python's `Scripts` folder, which may not be on your PATH. You'll see `traceback : The term 'traceback' is not recognized` if it's missing.

**Option A — Add to PATH for the current session only:**

```powershell
# Find Python's directory and add its Scripts folder to PATH
$pyDir = Split-Path -Parent (Get-Command python).Source
$scriptsDir = Join-Path $pyDir "Scripts"
$env:Path = $env:Path + ";" + $scriptsDir

# Now the traceback command works
traceback analyse examples/microservices/
```

**Option B — Add to PATH permanently (all future PowerShell windows):**

```powershell
$pyDir = Split-Path -Parent (Get-Command python).Source
$scriptsDir = Join-Path $pyDir "Scripts"
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";" + $scriptsDir, "User")
# Restart PowerShell after running this
```

**Option C — Use `python -m` directly (no PATH changes needed):**

```powershell
python -m tb_core.cli.commands analyse examples/microservices/
python -m tb_core.cli.commands tui
python -m tb_core.cli.commands report TB-TRC-LOGIN-001 --format markdown
```

After installing, verify:

```bash
traceback --version
```

## Quick Start

### Analyse a directory of logs

```bash
traceback analyse ./logs/
```

### Analyse a single file

```bash
traceback analyse app.log
```

### Analyse JSONL logs

```bash
traceback analyse app.jsonl --format jsonl
```

### List incidents

```bash
traceback incidents
```

### Show incident details

```bash
traceback show TB-001
```

### View incident timeline

```bash
traceback timeline TB-001
```

### Generate a Markdown report

```bash
traceback report TB-001 --format markdown
```

### Generate a JSON report

```bash
traceback report TB-001 --format json
```

### Launch the interactive TUI

```bash
traceback tui
```

### Analyse with the multi-service demo

```bash
traceback analyse examples/microservices/
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `traceback analyse <path>` | Analyse logs from a file or directory |
| `traceback incidents` | List all stored incidents |
| `traceback show <id>` | Show incident details |
| `traceback timeline <id>` | View incident timeline |
| `traceback report <id> --format <md\|json>` | Generate incident report |
| `traceback tui` | Launch interactive terminal UI |
| `traceback --version` | Show version |

## TUI Screens

The interactive TUI (`traceback tui`) has four screens:

- **Dashboard** — Event/incident statistics, most frequent exceptions, services involved
- **Incident Explorer** — Filterable table of all incidents by severity, service, date
- **Timeline Viewer** — Chronological event sequence with highlighted errors
- **Investigation View** — Root cause, evidence, cascade chain, debugging steps

Keyboard shortcuts: `q` quit, `d` dashboard, `i` incidents, `t` timeline, `r` export report

## Sample Demonstration

The `examples/microservices/` directory contains a complete multi-service incident:

- `frontend.log` — Frontend authentication request
- `auth.log` — Auth service with NullReferenceException
- `database.log` — Database returning null (user not found)
- `api.log` — API gateway returning HTTP 500

All four logs share trace ID `TRC-LOGIN-001`. Running:

```bash
traceback analyse examples/microservices/
```

detects the related events, groups them into one incident, reconstructs the
timeline, identifies the null reference exception, and suggests debugging steps.
This works completely offline without an AI API key.

## Secret Redaction

TraceBack automatically redacts sensitive information before saving, exporting,
or transmitting log data:

- API keys, access tokens, JWT tokens
- Passwords and authorization headers
- Database connection strings
- Email addresses (configurable)

Redacted values are replaced with `[REDACTED]`. Redaction is local-first —
nothing is transmitted externally.

## Incident History

TraceBack persists incident metadata to SQLite (`traceback_history.db` by
default). Previous investigations can be listed, searched, and deleted:

```bash
traceback incidents          # List all incidents
traceback show TB-001        # Show details
```

## Testing

```bash
uv run pytest tests/
```

Or:

```bash
pytest tests/
```

75 tests cover parsers, normalizer, correlator, timeline, analysis, redactor, and reporting.

## Project Structure

```
traceback-cli/
├── pyproject.toml
├── README.md
├── LICENSE
├── .gitignore
├── .env.example
├── src/tb_core/            # Main package
│   ├── cli/                # Typer CLI commands
│   ├── tui/                # Textual TUI (4 screens, widgets, styles)
│   ├── ingestion/          # Log loading, detection, parsing
│   ├── core/               # Event models, normalization, correlation
│   ├── analysis/           # Root cause, cascade, recommendations
│   ├── security/           # Secret redaction
│   ├── storage/            # SQLite incident history
│   ├── reporting/          # Markdown and JSON reports
│   └── utils/              # Timestamps and helpers
├── tests/                  # 75 pytest tests
├── examples/               # Sample log files
│   ├── microservices/      # Multi-service demo (frontend, auth, database, api)
│   ├── nodejs/             # Node.js error log
│   ├── python/             # Python error log
│   └── json/               # JSONL example
└── docs/
    └── architecture.md     # Architecture and pipeline diagram
```

## Architecture

The processing pipeline is:

```
LOG INPUT → INGESTION → FORMAT DETECTION → PARSING → NORMALISATION
    → REDACTION → CORRELATION → INCIDENT GROUPING → TIMELINE → ROOT-CAUSE
    → REPORT → CLI/TUI/SQLITE
```

See `docs/architecture.md` for the full Mermaid architecture diagram.

## Limitations

- Designed for local development logs and modest multi-service collections
- Not for massive-scale distributed observability workloads
- Correlation relies on request/trace IDs; events without identifiers may be missed
- AI integration is optional and never used for core event correlation

## License

MIT License. See `LICENSE` for details.
