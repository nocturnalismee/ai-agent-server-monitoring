"""Backward-compatibility shim for server_agent.filetail."""
from .collectors.filetail import FileTailer, safe_path_exists

__all__ = ["FileTailer", "safe_path_exists"]
