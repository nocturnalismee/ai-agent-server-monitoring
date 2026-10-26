"""Backward-compatibility shim for server_agent.telegram."""
from .notifiers.telegram import (
    _SEVERITY_EMOJI,  # noqa: F401
    TelegramNotifier,
    _e,  # noqa: F401
    _fmt_timestamp,  # noqa: F401
    _truncate_html,  # noqa: F401
    _utf16_len,  # noqa: F401
)

__all__ = ["TelegramNotifier"]
