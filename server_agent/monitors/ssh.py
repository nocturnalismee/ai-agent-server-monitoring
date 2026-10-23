from __future__ import annotations

import ipaddress
import re
import time
from pathlib import Path
from typing import Optional, Tuple

from ..models import Incident

SUCCESS_RE = re.compile(
    r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>[0-9a-fA-F:.]+)\s+port\s+(?P<port>\d+)",
    re.I,
)
FAIL_RE = re.compile(
    r"(?:Failed\s+\S+\s+for(?: invalid user)?\s+(?P<user>\S+)\s+from|Invalid user\s+(?P<invalid_user>\S+)\s+from)\s+(?P<ip>[0-9a-fA-F:.]+)",
    re.I,
)


class SSHMonitor:
    def __init__(self, config, state, tailer, logger):
        self.cfg = config
        self.state = state
        self.tailer = tailer
        self.logger = logger
        self.trusted = self._parse_networks(config.trusted_ssh_networks)

    def _parse_networks(self, values):
        nets = []
        for value in values:
            try:
                nets.append(ipaddress.ip_network(value, strict=False))
            except ValueError:
                self.logger.warning("Ignoring invalid TRUSTED_SSH_NETWORKS value: %s", value)
        return nets

    def _is_trusted(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self.trusted)
        except ValueError:
            return False

    def _auth_paths(self):
        paths = []
        for p in (self.cfg.auth_log, self.cfg.auth_log_rhel):
            if p and p not in paths and Path(p).exists():
                paths.append(p)
        return paths

    def _sample(self, line: str) -> str:
        line = line.rstrip()
        if len(line) <= self.cfg.max_log_sample_chars:
            return line
        return line[: self.cfg.max_log_sample_chars - 14] + " [truncated]"

    def collect(self):
        incidents = []
        for path in self._auth_paths():
            lines = self.tailer.read_new_lines(
                path,
                max_lines=self.cfg.max_log_lines_per_cycle,
                max_line_chars=self.cfg.max_log_line_chars,
            )
            for line in lines:
                success = SUCCESS_RE.search(line)
                if success:
                    user = success.group("user")
                    ip = success.group("ip")
                    method = success.group("method")
                    trusted = self._is_trusted(ip)

                    if self.cfg.ssh_alert_success:
                        severity = "CRITICAL" if user == "root" and self.cfg.ssh_alert_root_login else ("INFO" if trusted else "WARNING")
                        incidents.append(Incident(
                            kind="ssh_login",
                            severity=severity,
                            title=f"SSH login: {user} from {ip}",
                            summary=f"Successful SSH {method} login for {user} from {ip}" + (" (trusted network)" if trusted else ""),
                            fingerprint=f"ssh:success:{user}:{ip}",
                            details={
                                "user": user, "source_ip": ip, "method": method,
                                "trusted_network": trusted, "raw_log": self._sample(line)
                            },
                        ))
                    self.state.clear_ssh_failures(ip)
                    continue

                failed = FAIL_RE.search(line)
                if failed:
                    user = failed.groupdict().get("user") or failed.groupdict().get("invalid_user") or "unknown"
                    ip = failed.group("ip")
                    count = self.state.add_ssh_failure(
                        ip, time.time(), self.cfg.ssh_failed_window_seconds
                    )

                    if self.cfg.ssh_alert_failed_burst and count >= self.cfg.ssh_failed_threshold:
                        incidents.append(Incident(
                            kind="ssh_bruteforce",
                            severity="CRITICAL",
                            title=f"SSH failed-login burst from {ip}",
                            summary=f"{count} failed SSH attempts from {ip} within {self.cfg.ssh_failed_window_seconds}s",
                            fingerprint=f"ssh:failed-burst:{ip}",
                            details={
                                "source_ip": ip,
                                "attempts_in_window": count,
                                "last_user": user,
                                "window_seconds": self.cfg.ssh_failed_window_seconds,
                                "raw_log": self._sample(line),
                            },
                        ))
        return incidents
