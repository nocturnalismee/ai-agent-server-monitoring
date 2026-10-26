"""Backward-compatibility shim for server_agent.state."""
from .core.state import StateStore, _latest_timestamp, _recent_timestamp  # noqa: F401

__all__ = ["StateStore"]
