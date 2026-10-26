"""Backward-compatibility shim for server_agent.emailer."""
from .notifiers.emailer import EmailNotifier

__all__ = ["EmailNotifier"]
