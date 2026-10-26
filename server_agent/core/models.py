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
    evidence: str = ""

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
            "evidence": self.evidence,
        }


@dataclass
class ServerMetadata:
    hostname: str = ""
    short_name: str = ""
    os_name: str = ""
    os_version: str = ""
    os_family: str = ""  # debian, rhel, arch, etc.
    kernel: str = ""
    panel: str = "Standalone"  # cPanel, CyberPanel, aaPanel, Plesk, CloudPanel, HestiaCP, Standalone
    panel_version: str = ""
    web_server: str = ""  # Nginx, Apache, OpenLiteSpeed, LiteSpeed, Caddy, etc.
    database: str = ""  # MySQL, MariaDB, PostgreSQL, Redis, etc.
    firewall: str = ""  # UFW, firewalld, CSF, iptables, etc.
    package_manager: str = ""  # apt, dnf, yum, etc.
    features: Dict[str, Any] = field(default_factory=dict)  # e.g. {"cagefs": True, "lve": True}

    def badge(self) -> str:
        parts = []
        if self.os_name:
            ver = f" {self.os_version}" if self.os_version else ""
            parts.append(f"{self.os_name}{ver}")
        if self.panel and self.panel != "Standalone":
            parts.append(self.panel)
        if self.web_server:
            parts.append(self.web_server)
        return " · ".join(parts) if parts else "Linux Server"
