"""Backward-compatibility shim for server_agent.logging_setup."""
from .core.logging_setup import setup_logging

__all__ = ["setup_logging"]
