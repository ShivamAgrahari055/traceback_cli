"""Configuration for the optional LLM intelligence layer.

All settings are read from environment variables. The application is
fully functional without any AI provider configured.
"""

from __future__ import annotations

import os
from typing import Optional


def get_bool_env(name: str, default: bool = False) -> bool:
    """Read a boolean environment variable."""
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def get_str_env(name: str, default: Optional[str] = None) -> Optional[str]:
    """Read a string environment variable."""
    val = os.getenv(name)
    if val is None or val.strip() == "":
        return default
    return val.strip()


def get_int_env(name: str, default: Optional[int] = None) -> Optional[int]:
    """Read an integer environment variable."""
    val = os.getenv(name)
    if val is None or val.strip() == "":
        return default
    try:
        return int(val.strip())
    except ValueError:
        return default


class AIConfig:
    """Configuration for the optional AI layer.

    Attributes:
        enabled: Whether the AI layer is active.
        provider: Provider name (e.g. "openai_compatible", "gemini").
        api_key: API key (kept server-side, never logged).
        model: Model name to use.
        base_url: Optional base URL for the provider API.
        timeout: Request timeout in seconds.
        max_tokens: Maximum tokens for the response.
        temperature: Sampling temperature.
    """

    def __init__(self) -> None:
        self.enabled: bool = get_bool_env("TRACEBACK_AI_ENABLED", False)
        self.provider: str = get_str_env("TRACEBACK_AI_PROVIDER", "openai_compatible")
        self.api_key: Optional[str] = get_str_env("TRACEBACK_AI_API_KEY")
        self.model: str = get_str_env("TRACEBACK_AI_MODEL", "gemini-pro")
        self.base_url: Optional[str] = get_str_env("TRACEBACK_AI_BASE_URL")
        self.timeout: int = get_int_env("TRACEBACK_AI_TIMEOUT", 30) or 30
        self.max_tokens: int = get_int_env("TRACEBACK_AI_MAX_TOKENS", 1000) or 1000
        self.temperature: float = get_int_env("TRACEBACK_AI_TEMPERATURE", 2) / 10.0 or 0.2

    @property
    def is_configured(self) -> bool:
        """True if AI is enabled and has the minimum required credentials."""
        return self.enabled and bool(self.api_key)

    def redact_for_log(self) -> dict:
        """Return a safe copy of config for logging (API key masked)."""
        return {
            "enabled": self.enabled,
            "provider": self.provider,
            "model": self.model,
            "base_url": self.base_url,
            "timeout": self.timeout,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "api_key_set": bool(self.api_key),
        }
