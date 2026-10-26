from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from ..core.models import Incident, ServerMetadata


class BaseNotifier(ABC):
    def __init__(self, config, logger, metadata: Optional[ServerMetadata] = None):
        self.cfg = config
        self.logger = logger
        self.metadata = metadata

    def set_metadata(self, metadata: ServerMetadata) -> None:
        self.metadata = metadata

    @abstractmethod
    def send(self, incident: Incident) -> bool:
        """Send an incident notification. Return True on success."""
        raise NotImplementedError

    @abstractmethod
    def send_test(self) -> bool:
        """Send a test notification to verify transport configuration."""
        raise NotImplementedError
