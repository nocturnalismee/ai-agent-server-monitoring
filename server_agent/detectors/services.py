from __future__ import annotations

import subprocess
from pathlib import Path
from typing import List, Set


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
