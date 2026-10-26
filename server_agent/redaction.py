"""Backward-compatibility shim for server_agent.redaction."""
from .core.redaction import (
    REDACTED,
    sanitize_incident,
    sanitize_text,
    sanitize_value,
)

__all__ = ["REDACTED", "sanitize_incident", "sanitize_text", "sanitize_value"]
