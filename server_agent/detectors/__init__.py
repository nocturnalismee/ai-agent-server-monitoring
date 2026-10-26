"""System, panel, and service detectors."""
from .environment import EnvironmentDetector
from .services import ServiceDetector

__all__ = ["EnvironmentDetector", "ServiceDetector"]
