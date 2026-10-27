from __future__ import annotations

import os
import subprocess
from typing import Dict, List, Optional, Tuple

import psutil

from ..core.models import Incident
from ..detectors.service_profiles import resolve_targets
from ..detectors.services import ResolvedService, ServiceDetector, ServiceResolver


class HealthMonitor:
    def __init__(self, config, state, logger, panel: Optional[str] = None):
        self.cfg = config
        self.state = state
        self.log = logger
        self.panel = panel
        self.resolver = ServiceResolver(logger)

        legacy = list(config.services)
        if config.auto_detect_services:
            legacy = ServiceDetector(logger).filter_installed_services(legacy)
        self.monitored_services = legacy

        # Prime psutil's non-blocking CPU counter. Subsequent calls are based
        # on elapsed time and do not pause the monitoring loop for one second.
        psutil.cpu_percent(interval=None)

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
        try:
            p = subprocess.run(
                ["systemctl", "is-active", "--", service],
                capture_output=True, text=True, timeout=3, check=False
            )
            state = (p.stdout or p.stderr).strip()
            return ("active" if p.returncode == 0 and state == "active" else state or "unknown", "")
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            return "unknown", str(exc)

    def collect_services(self) -> List[Incident]:
        incidents: List[Incident] = []
        targets = self._service_targets()
        by_unit: Dict[str, Tuple[str, bool, ResolvedService]] = {}
        for name, required in targets:
            item = self.resolver.resolve(name)
            existing = by_unit.get(item.unit)
            if existing is not None and existing[1] and not required:
                continue
            by_unit[item.unit] = (name, required, item)
        resolved = list(by_unit.values())

        for name, required, item in resolved:
            if item.state == "not-found":
                if not required:
                    continue
                incidents.append(
                    self._service_incident(name, item.unit, "not-found", True, "", 0)
                )
                continue
            if item.state == "unknown":
                if required or self.cfg.alert_on_missing_service:
                    incidents.append(
                        self._service_incident(
                            name,
                            item.unit,
                            "unknown",
                            required,
                            "",
                            0,
                            severity="WARNING",
                        )
                    )
                continue

            state, error = self._service_state(item.unit)
            key = f"service:{name}"
            if state == "active":
                self.state.clear_service_failure(key)
                was_problem = self.state.set_health_active(key, False)
                if was_problem and self.cfg.recovery_alerts:
                    incidents.append(
                        Incident(
                            kind="recovery",
                            severity="INFO",
                            title=f"Service {name} recovered",
                            summary=f"Service {name} ({item.unit}) is active again.",
                            fingerprint=f"recovery:{key}",
                            details={
                                "service": name,
                                "unit": item.unit,
                                "state": "active",
                            },
                        )
                    )
                continue

            failures = self.state.increment_service_failure(key)
            if state == "failed" or failures >= self.cfg.service_failure_threshold:
                severity = "CRITICAL" if required else "WARNING"
                incidents.append(
                    self._service_incident(
                        name, item.unit, state, required, error, failures, severity
                    )
                )
        return incidents

    def _service_targets(self) -> List[Tuple[str, bool]]:
        legacy = list(self.cfg.services or [])
        if legacy and self.cfg.auto_detect_services:
            legacy = ServiceDetector(self.log).filter_installed_services(legacy)
        required, optional = resolve_targets(
            self.cfg.service_profile,
            self.panel,
            legacy,
            self.cfg.services_required or [],
            self.cfg.services_optional or [],
        )
        return [(name, True) for name in required] + [
            (name, False) for name in optional
        ]

    def _service_incident(
        self,
        name: str,
        unit: str,
        state: str,
        required: bool,
        error: str,
        failures: int,
        severity: str = "CRITICAL",
    ) -> Incident:
        key = f"service:{name}"
        self.state.set_health_active(key, True)
        if state == "not-found":
            title = f"Service {name} is not installed"
        elif state == "unknown":
            title = f"Service {name} state is unknown"
        else:
            title = f"Service {name} is not active"
        details = {
            "service": name,
            "unit": unit,
            "state": state,
            "required": required,
            "consecutive_failures": failures,
        }
        if error:
            details["error"] = error
        return Incident(
            kind="service",
            severity=severity,
            title=title,
            summary=f"Service {name} ({unit}) reported state '{state}'.",
            fingerprint=key,
            details=details,
        )

    def collect(self) -> List[Incident]:
        incidents: List[Incident] = []

        cpu = psutil.cpu_percent(interval=None)
        memory = psutil.virtual_memory().percent

        for incident in (
            self._metric_incident("CPU", cpu, self.cfg.cpu_warning, self.cfg.cpu_critical),
            self._metric_incident("Memory", memory, self.cfg.memory_warning, self.cfg.memory_critical),
        ):
            if incident:
                incidents.append(incident)

        cpu_count = max(psutil.cpu_count() or 1, 1)
        getloadavg = getattr(os, "getloadavg", None)
        if getloadavg is not None:
            try:
                load1 = getloadavg()[0]
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

        incidents.extend(self.collect_services())

        return incidents
