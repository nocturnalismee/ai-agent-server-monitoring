"""Backward-compatibility shim for server_agent.telegram."""
from .notifiers.telegram import TelegramNotifier, _SEVERITY_EMOJI, _e, _fmt_timestamp

__all__ = ["TelegramNotifier"]
