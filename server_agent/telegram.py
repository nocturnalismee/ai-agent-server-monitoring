"""Backward-compatibility shim for server_agent.telegram."""
from .notifiers.telegram import (
    TelegramNotifier,
    _SEVERITY_EMOJI,
    _e,
    _fmt_timestamp,
    _truncate_html,
    _utf16_len,
)

__all__ = ["TelegramNotifier"]
