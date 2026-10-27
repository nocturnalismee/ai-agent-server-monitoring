from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set

from .service_profiles import alias_candidates


@dataclass(frozen=True)
class ResolvedService:
    name: str
    unit: str
    installed: bool
    state: str


class ServiceResolver:
    SYSTEMD_DIRS = (
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
    )

    def __init__(self, logger=None):
        self.logger = logger
        self._cache: Dict[str, ResolvedService] = {}

    def resolve(self, name: str) -> ResolvedService:
        cached = self._cache.get(name)
        if cached is not None and cached.installed:
            return cached

        candidates = alias_candidates(name)
        for candidate in candidates:
            unit = self._find_unit_file(candidate)
            if unit:
                result = ResolvedService(name, unit, True, "installed")
                self._cache[name] = result
                return result

        saw_unknown = False
        for candidate in candidates:
            state, unit = self._query_unit(candidate)
            if state == "unknown":
                saw_unknown = True
                continue
            if state == "installed":
                result = ResolvedService(name, unit, True, "installed")
                self._cache[name] = result
                return result

        if saw_unknown:
            return ResolvedService(name, candidates[0], False, "unknown")
        return ResolvedService(name, candidates[0], False, "not-found")

    def _find_unit_file(self, candidate: str) -> str:
        unit = candidate if candidate.endswith(".service") else f"{candidate}.service"
        for directory in self.SYSTEMD_DIRS:
            path = f"{directory}/{unit}"
            try:
                if os.path.exists(path):
                    return unit
            except (PermissionError, OSError):
                continue
        return ""

    def _query_unit(self, candidate: str) -> tuple:
        try:
            proc = subprocess.run(
                ["systemctl", "show", "-p", "Id", "-p", "LoadState", "--", candidate],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return "unknown", ""

        data: Dict[str, str] = {}
        for line in (proc.stdout or "").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                data[key.strip()] = value.strip()
        load_state = data.get("LoadState", "")
        if proc.returncode != 0 or not load_state or load_state == "not-found":
            return "not-found", ""
        return "installed", data.get("Id") or candidate


class ServiceDetector:
    """Discovers which systemd services are actually installed/enabled on this system."""

    COMMON_SERVICES = [
        "nginx",
        "apache2",
        "httpd",
        "lshttpd",
        "lsws",
        "ssh",
        "sshd",
        "mysql",
        "mariadb",
        "mysqld",
        "postgresql",
        "redis",
        "redis-server",
        "docker",
        "php-fpm",
    ]

    def __init__(self, logger=None):
        self.logger = logger
        self._installed_cache: Set[str] = set()

    def filter_installed_services(self, candidate_services: List[str]) -> List[str]:
        """Given a list of service names, return only those that exist on the system."""
        if not candidate_services:
            return []

        installed = []
        for srv in candidate_services:
            srv = srv.strip()
            if not srv:
                continue
            if self._is_service_installed(srv):
                installed.append(srv)
            else:
                if self.logger:
                    self.logger.debug("Service %s is not installed; skipping from watch list", srv)

        return installed

    def _is_service_installed(self, service: str) -> bool:
        if service in self._installed_cache:
            return True

        # Quick check in systemd unit search paths
        unit_name = service if service.endswith(".service") else f"{service}.service"
        for p in (
            f"/etc/systemd/system/{unit_name}",
            f"/lib/systemd/system/{unit_name}",
            f"/usr/lib/systemd/system/{unit_name}",
        ):
            try:
                if Path(p).exists():
                    self._installed_cache.add(service)
                    return True
            except (PermissionError, OSError):
                pass

        # Fallback to systemctl status/cat
        try:
            p = subprocess.run(
                ["systemctl", "status", "--", service],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
            # If output contains "not-found" or unit could not be found, return False
            combined = (p.stdout + p.stderr).lower()
            if "not-found" in combined or "could not be found" in combined:
                return False

            self._installed_cache.add(service)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            # Not systemd or timed out
            return True  # Be conservative if systemctl is missing
