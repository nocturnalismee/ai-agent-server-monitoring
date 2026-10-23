from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple

import psutil

from ..models import Incident


class HealthMonitor:
    def __init__(self, config, state, logger):
        self.cfg = config
        self.state = state
        self.logger = logger

    @staticmethod
    def _severity(value: float, warning: float, critical: float):
        if value >= critical:
            return "CRITICAL"
        if value >= warning:
            return "WARNING"
        return None

    def _metric_incident(self, name, value, warning, critical, unit="%"):
        severity = self._severity(value, warning, critical)
        key = f"health:{name}"
        was_active = self.state.set_health_active(key, severity is not None)

        if severity:
            return Incident(
                kind="health",
                severity=severity,
                title=f"{name} threshold exceeded",
                summary=f"{name} is {value:.1f}{unit}",
                fingerprint=key,
                details={"metric": name, "value": value, "unit": unit,
                         "warning_threshold": warning, "critical_threshold": critical},
            )

        if was_active and self.cfg.recovery_alerts:
            return Incident(
                kind="recovery",
                severity="INFO",
                title=f"{name} recovered",
                summary=f"{name} returned to normal: {value:.1f}{unit}",
                fingerprint=f"recovery:{key}",
                details={"metric": name, "value": value, "unit": unit},
            )
        return None

    def _service_state(self, service: str) -> Tuple[str, str]:
        if not shutil.which("systemctl"):
            return "unknown", "systemctl not found"
        try:
            loaded = subprocess.run(
                ["systemctl", "show", service, "--property=LoadState", "--value"],
                capture_output=True, text=True, timeout=5, check=False
            )
            load_state = (loaded.stdout or "").strip()
            if load_state in {"not-found", ""}:
                return "not-found", ""

            p = subprocess.run(
                ["systemctl", "is-active", service],
                capture_output=True, text=True, timeout=5, check=False
            )
            state = (p.stdout or p.stderr).strip()
            return ("active" if p.returncode == 0 and state == "active" else state or "inactive", "")
        except (subprocess.TimeoutExpired, OSError) as exc:
            return "unknown", str(exc)

    def collect(self) -> List[Incident]:
        incidents: List[Incident] = []

        cpu = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory().percent

        for incident in (
            self._metric_incident("CPU", cpu, self.cfg.cpu_warning, self.cfg.cpu_critical),
            self._metric_incident("Memory", memory, self.cfg.memory_warning, self.cfg.memory_critical),
        ):
            if incident:
                incidents.append(incident)

        cpu_count = max(psutil.cpu_count() or 1, 1)
        try:
            load1 = os.getloadavg()[0]
            normalized = load1 / cpu_count
            incident = self._metric_incident(
                "Load-per-CPU",
                normalized,
                self.cfg.load_warning_per_cpu,
                self.cfg.load_critical_per_cpu,
                "",
            )
            if incident:
                incident.details["load_1m"] = load1
                incident.details["cpu_count"] = cpu_count
                incidents.append(incident)
        except OSError:
            pass

        for mount in self.cfg.disk_paths:
            try:
                usage = psutil.disk_usage(mount).percent
            except (FileNotFoundError, PermissionError, OSError):
                continue
            incident = self._metric_incident(
                f"Disk {mount}", usage, self.cfg.disk_warning, self.cfg.disk_critical
            )
            if incident:
                incidents.append(incident)

        for service in self.cfg.services:
            state, err = self._service_state(service)
            if state == "unknown" and not self.cfg.alert_on_missing_service:
                continue

            key = f"service:{service}"
            active = state == "active"
            was_problem = self.state.set_health_active(key, not active)

            if not active:
                # "not-found" is ignored by default because nginx/apache and ssh/sshd names differ by distro.
                if state in {"not-found", "unknown"} and not self.cfg.alert_on_missing_service:
                    continue
                incidents.append(Incident(
                    kind="service",
                    severity="CRITICAL",
                    title=f"Service {service} is not active",
                    summary=f"systemd reports {service}: {state}",
                    fingerprint=key,
                    details={"service": service, "state": state, "error": err},
                ))
            elif was_problem and self.cfg.recovery_alerts:
                incidents.append(Incident(
                    kind="recovery",
                    severity="INFO",
                    title=f"Service {service} recovered",
                    summary=f"{service} is active again",
                    fingerprint=f"recovery:{key}",
                    details={"service": service, "state": state},
                ))

        return incidents
