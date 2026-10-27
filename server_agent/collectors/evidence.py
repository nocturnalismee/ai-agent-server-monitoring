from __future__ import annotations

import re
import subprocess
from typing import Optional

from ..core.models import Incident

_UNIT_RE = re.compile(r"^[a-zA-Z0-9_@.:-]+$")


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
                unit = incident.details.get("unit")
                service = incident.details.get("service", "")
                if unit:
                    return self._collect_service_journal(service, unit)
                return self._collect_service_journal(service)

            elif incident.kind == "health":
                metric = incident.details.get("metric", "")
                if metric == "CPU" or "Load" in metric:
                    return self._collect_top_cpu_processes()
                elif metric == "Memory":
                    return self._collect_top_memory_processes()
                elif "Disk" in metric:
                    # Prefer the structured metric name (e.g. "Disk /var") over
                    # parsing the human-readable title.
                    mount = metric[len("Disk "):].strip() if metric.startswith("Disk ") else ""
                    if not mount:
                        mount = incident.title.replace("Disk ", "").replace(" threshold exceeded", "").strip()
                    return self._collect_disk_overview(mount)

        except Exception as exc:
            if self.logger:
                self.logger.debug("Evidence collection error for %s: %s", incident.fingerprint, exc)
        return ""

    def _collect_service_journal(self, service: str, unit: Optional[str] = None) -> str:
        target = unit or service
        # Security hardening: reject any target that contains flags or shell metacharacters.
        if not target or not _UNIT_RE.fullmatch(target):
            return ""
        parts = []
        try:
            proc = subprocess.run(
                ["journalctl", "-u", target, "-n", str(self.max_lines), "--no-pager"],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            if proc.stdout.strip():
                parts.append(
                    f"--- journalctl -u {target} (last {self.max_lines} lines) ---\n"
                    f"{proc.stdout.strip()}"
                )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
        try:
            proc = subprocess.run(
                ["systemctl", "status", "--no-pager", "-l", "--", target],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            streams = [
                text.strip()
                for text in (proc.stdout, proc.stderr)
                if text and text.strip()
            ]
            output = "\n".join(streams)
            if output:
                lines = output.splitlines()[: self.max_lines]
                parts.append("--- systemctl status " + target + " ---\n" + "\n".join(lines))
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
        return "\n\n".join(parts)

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
