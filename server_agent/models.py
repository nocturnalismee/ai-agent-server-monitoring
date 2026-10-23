from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict


@dataclass
class Incident:
    kind: str
    severity: str
    title: str
    summary: str
    fingerprint: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    ai_analysis: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "title": self.title,
            "summary": self.summary,
            "fingerprint": self.fingerprint,
            "details": self.details,
            "timestamp": self.timestamp,
            "ai_analysis": self.ai_analysis,
        }
