from __future__ import annotations

import re
import subprocess
from typing import Optional

from ..core.models import Incident


class EvidenceCollector:
    """Collects real-time diagnostic evidence (journalctl logs, top processes) for an incident."""

    def __init__(self, max_lines: int = 15, timeout: int = 3, logger=None):
        self.max_lines = max_lines
        self.timeout = timeout
        self.logger = logger

    def collect(self, incident: Incident) -> str:
        """Return captured system evidence text, or empty string if not applicable/failed."""
        try:
            if incident.kind == "service":
                service = incident.details.get("service")
                if service:
                    return self._collect_service_journal(service)

            elif incident.kind == "health":
                metric = incident.details.get("metric", "")
                if metric == "CPU" or "Load" in metric:
                    return self._collect_top_cpu_processes()
                elif metric == "Memory":
                    return self._collect_top_memory_processes()
                elif "Disk" in metric:
                    mount = incident.title.replace("Disk ", "").replace(" threshold exceeded", "").strip()
                    return self._collect_disk_overview(mount)

        except Exception as exc:
            if self.logger:
                self.logger.debug("Evidence collection error for %s: %s", incident.fingerprint, exc)
        return ""

    def _collect_service_journal(self, service: str) -> str:
        # Security hardening: reject any service name that contains non-alphanumeric chars or flags
        if not re.match(r"^[a-zA-Z0-9_@.-]+$", service):
            return ""
        try:
            p = subprocess.run(
                ["journalctl", "-u", service, "-n", str(self.max_lines), "--no-pager"],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            out = (p.stdout or "").strip()
            if out:
                return f"--- journalctl -u {service} (last {self.max_lines} lines) ---\n{out}"
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
        return ""

    def _collect_top_cpu_processes(self) -> str:
        try:
            p = subprocess.run(
                ["ps", "-eo", "pid,user,%cpu,%mem,comm", "--sort=-%cpu"],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            lines = (p.stdout or "").strip().splitlines()[:6]
            if lines:
                return "--- Top 5 CPU Processes ---\n" + "\n".join(lines)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
        return ""

    def _collect_top_memory_processes(self) -> str:
        try:
            p = subprocess.run(
                ["ps", "-eo", "pid,user,%mem,%cpu,comm", "--sort=-%mem"],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            lines = (p.stdout or "").strip().splitlines()[:6]
            if lines:
                return "--- Top 5 Memory Processes ---\n" + "\n".join(lines)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
        return ""

    def _collect_disk_overview(self, mount: str) -> str:
        target = mount if mount.startswith("/") else "/"
        if not re.match(r"^[a-zA-Z0-9/_.-]+$", target):
            target = "/"
        try:
            p = subprocess.run(
                ["df", "-h", "--", target],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            out = (p.stdout or "").strip()
            if out:
                return f"--- df -h {target} ---\n{out}"
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
        return ""
