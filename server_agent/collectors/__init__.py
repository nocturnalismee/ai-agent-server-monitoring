"""Log and evidence collectors."""
from .evidence import EvidenceCollector
from .filetail import FileTailer, safe_path_exists

__all__ = ["EvidenceCollector", "FileTailer", "safe_path_exists"]
