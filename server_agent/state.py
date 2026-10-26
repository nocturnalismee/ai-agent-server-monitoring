"""Backward-compatibility shim for server_agent.state."""
from .core.state import StateStore, _recent_timestamp, _latest_timestamp

__all__ = ["StateStore"]
