"""Backward-compatibility shim for server_agent.models."""
from .core.models import Incident, ServerMetadata

__all__ = ["Incident", "ServerMetadata"]
