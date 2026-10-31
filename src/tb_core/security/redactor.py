"""Secret redaction engine.

Detects sensitive information (API keys, JWT tokens, passwords, database
connection strings, authorization headers, email addresses) and replaces
values with [REDACTED] before saving, exporting or transmitting log data.

Default operation is local-first: nothing is transmitted externally.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

REDACTION_TOKEN = "[REDACTED]"

# Pattern name -> (regex, replacement). Values are replaced; keys/labels kept
# where useful so surrounding log information remains meaningful.
DEFAULT_PATTERNS: Dict[str, str] = {
    "API_KEY": r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*\S+",
    "JWT": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*",
    "PASSWORD": r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+",
    "CONNECTION_STRING": r"(?i)(mongodb|postgres|postgresql|mysql|redis)://\S+",
    "AUTHORIZATION": r"(?i)authorization\s*[:=]\s*\S+",
    "EMAIL": r"[\w.+-]+@[\w.-]+\.\w+",
}


class SecretRedactor:
    """Redact secrets from log text."""

    def __init__(self, patterns: Optional[Dict[str, str]] = None):
        self.patterns: Dict[str, str] = dict(DEFAULT_PATTERNS)
        if patterns:
            self.patterns.update(patterns)
        self._compiled = {
            name: re.compile(pat) for name, pat in self.patterns.items()
        }

    def redact(self, text: str) -> str:
        """Return text with secret values replaced by [REDACTED]."""
        if not text:
            return text
        redacted = text
        for _name, pattern in self._compiled.items():
            redacted = pattern.sub(REDACTION_TOKEN, redacted)
        return redacted

    def redact_event_message(self, message: Optional[str]) -> Optional[str]:
        if message is None:
            return None
        return self.redact(message)

    def redact_stack_trace(self, stack_trace: Optional[str]) -> Optional[str]:
        if stack_trace is None:
            return None
        return self.redact(stack_trace)

    def add_pattern(self, name: str, pattern: str) -> None:
        self.patterns[name] = pattern
        self._compiled[name] = re.compile(pattern)

    def list_patterns(self) -> List[str]:
        return list(self.patterns.keys())
