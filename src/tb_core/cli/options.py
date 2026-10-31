"""Shared CLI option definitions for TraceBack commands."""

from typing import Optional

import typer


def file_path() -> str:
    """Typer callback that validates a file or directory path exists."""
    return typer.Argument(..., help="Path to file, directory, or log source")


def format_option(default: str = "auto") -> str:
    """Return the --format option as a Typer param value."""
    return typer.Option(
        default,
        "--format",
        "-f",
        help="Input log format: auto, json, jsonl, text, python, node",
    )
