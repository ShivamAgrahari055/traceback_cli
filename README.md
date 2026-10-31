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
| AI (optional) | OpenAI-compatible provider (no new deps) |

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

### Ask a question about an incident (requires AI)

```bash
traceback ask TB-001 "Why did this incident happen?"
traceback ask TB-001 "Which service should I investigate first?"
traceback ask TB-001 "What evidence supports the root cause?"
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
| `traceback ask <id> "<question>"` | Ask AI a question about an incident |
| `traceback tui` | Launch interactive terminal UI |
| `traceback --version` | Show version |

## Optional AI Intelligence Layer

TraceBack includes an optional LLM-powered intelligence layer that enriches
deterministic root-cause analysis with causal explanations, confidence
calibration, and incident Q&A. The application is **fully functional without
AI** — it is disabled by default.

### Enable AI

Copy `.env.example` to `.env` and set:

```powershell
# Enable the AI layer
$env:TRACEBACK_AI_ENABLED="true"

# Set your API key (kept server-side, never logged)
$env:TRACEBACK_AI_API_KEY="your-api-key-here"

# Optional: provider, model, base URL
$env:TRACEBACK_AI_PROVIDER="openai_compatible"
$env:TRACEBACK_AI_MODEL="gemini-pro"
$env:TRACEBACK_AI_BASE_URL=""   # blank for OpenAI, set for Groq/local/proxy
```

### Provider examples

| Provider | `TRACEBACK_AI_PROVIDER` | `TRACEBACK_AI_BASE_URL` | `TRACEBACK_AI_MODEL` |
|----------|------------------------|------------------------|---------------------|
| OpenAI | `openai_compatible` | (blank) | `gpt-3.5-turbo` |
| Groq | `openai_compatible` | `https://api.groq.com/openai/v1` | `mixtral-8x7b-32768` |
| Local (llama.cpp) | `openai_compatible` | `http://localhost:8080/v1` | `any` |
| Gemini (via OpenAI proxy) | `openai_compatible` | `https://generativelanguage.googleapis.com/v1beta/openai/` | `gemini-pro` |

### AI commands

When AI is enabled, two new capabilities unlock:

1. **`traceback analyse`** — Automatically enriches the deterministic report with an **AI-Enhanced Investigation** section (root-cause hypothesis, causal chain, confidence explanation, missing evidence, limitations).

2. **`traceback ask <id> "<question>"`** — Incident-specific Q&A with event ID citations:

   ```powershell
   traceback ask TB-TRC-LOGIN-001 "Why did this incident happen?"
   traceback ask TB-TRC-LOGIN-001 "Which service should I investigate first?"
   traceback ask TB-TRC-LOGIN-001 "What evidence supports the root cause?"
   traceback ask TB-TRC-LOGIN-001 "Explain this to a junior developer"
   ```

### AI security

- **Secrets redacted before anything is sent** — API keys, passwords, JWTs, connection strings, emails are replaced with `[REDACTED]`
- **Only incident evidence is transmitted** — never entire log directories
- **API keys stay server-side** — never logged or displayed
- **AI is opt-in** — disabled by default; deterministic analysis never calls any external service

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

99 tests cover parsers, normalizer, correlator, timeline, analysis, redactor,
reporting, and the optional AI layer (all mocked — no real API calls).

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
│   ├── ai/                 # Optional LLM intelligence layer (config, models, provider, manager, rca)
│   ├── security/           # Secret redaction
│   ├── storage/            # SQLite incident history
│   ├── reporting/          # Markdown and JSON reports
│   └── utils/              # Timestamps and helpers
├── tests/                  # 99 pytest tests
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

The optional AI layer plugs into the root-cause and reporting stages:

```
DETERMINISTIC RCA → LLM ENRICHMENT (optional) → MARKDOWN/JSON REPORT
```

See `docs/architecture.md` for the full Mermaid architecture diagram.

## Limitations

- Designed for local development logs and modest multi-service collections
- Not for massive-scale distributed observability workloads
- Correlation relies on request/trace IDs; events without identifiers may be missed
- AI integration is optional and never used for core event correlation
- AI layer requires an API key and is disabled by default
- AI hypotheses are clearly labelled and should be verified against log evidence

## License

MIT License. See `LICENSE` for details.
