# TraceBack 🔍

TraceBack is a developer tool that converts scattered application logs and stack traces into a chronological incident timeline, helping developers understand what happened before an error occurred.

## 🚀 Core Concept
Instead of manually searching through thousands of log lines, TraceBack automatically:
1. **Ingests** logs from multiple sources (JSON, Text, Python/Node traces).
2. **Correlates** events using Request/Trace IDs.
3. **Reconstructs** the timeline of the incident.
4. **Infers** the root cause using a causal reasoning engine.

## 🛠️ Technology Stack
- **Language**: Python 3.12+
- **CLI/TUI**: Typer, Textual, Rich
- **Data**: Pydantic, SQLite
- **Analysis**: Custom Rule-based Causal Engine

## 📁 Project Structure
- `src/traceback/ingestion`: Log parsing and normalization.
- `src/traceback/core`: Correlation and timeline reconstruction.
- `src/traceback/analysis`: Root-cause and cascade analysis.
- `src/traceback/tui`: Interactive terminal dashboard.
