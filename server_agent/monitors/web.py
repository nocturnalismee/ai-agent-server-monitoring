from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import List

from ..filetail import safe_path_exists
from ..models import Incident

ERROR_PATTERNS = {
    "upstream timeout": re.compile(r"upstream timed out", re.I),
    "connection refused": re.compile(r"connect\(\) failed|connection refused", re.I),
    "permission denied": re.compile(r"permission denied", re.I),
    "php/fcgi": re.compile(r"fastcgi|php[-_ ]?fpm|primary script unknown", re.I),
    "litespeed": re.compile(r"litespeed|lsapi|lshttpd", re.I),
    "resource pressure": re.compile(r"too many open files|worker_connections are not enough|cannot allocate memory", re.I),
    "apache error": re.compile(r"\[(?:error|crit|alert|emerg)\]", re.I),
    "5xx": re.compile(r"\b50[0-9]\b"),
}


class WebLogMonitor:
    def __init__(self, config, tailer, logger):
        self.cfg = config
        self.tailer = tailer
        self.logger = logger

    def _analyze(self, server: str, path: str, lines: List[str]):
        if not lines:
            return None

        categories = Counter()
        matched = []
        for line in lines:
            found = False
            for name, pattern in ERROR_PATTERNS.items():
                if pattern.search(line):
                    categories[name] += 1
                    found = True
            if found:
                matched.append(line.rstrip())

        # Error logs generally contain only errors, so include otherwise-unclassified new lines too.
        if not matched:
            matched = [x.rstrip() for x in lines if x.strip()]
            if matched:
                categories["other"] = len(matched)

        if len(matched) < self.cfg.web_error_batch_threshold:
            return None

        severity = "CRITICAL" if (
            categories["resource pressure"] > 0
            or categories["connection refused"] >= 5
            or len(matched) >= 50
        ) else "WARNING"

        samples = [self._sample(line) for line in matched[-8:]]
        category_text = ", ".join(f"{k}={v}" for k, v in categories.most_common()) or "unclassified"
        return Incident(
            kind="web",
            severity=severity,
            title=f"{server} errors detected",
            summary=f"{len(matched)} new {server} error-log entries; {category_text}",
            fingerprint=f"web:{server}:{':'.join(sorted(categories.keys()))}",
            details={
                "server": server,
                "log_path": path,
                "new_error_count": len(matched),
                "categories": dict(categories),
                "samples": samples,
            },
        )

    def _sample(self, line: str) -> str:
        line = line.rstrip()
        if len(line) <= self.cfg.max_log_sample_chars:
            return line
        return line[: self.cfg.max_log_sample_chars - 14] + " [truncated]"

    @staticmethod
    def _server_name(path: str) -> str:
        normalized = path.lower()
        if "lsws" in normalized or "openlitespeed" in normalized:
            return "LiteSpeed"
        if "directadmin" in normalized:
            return "DirectAdmin"
        if "plesk" in normalized or "sw-cp-server" in normalized:
            return "Plesk"
        if "cyberpanel" in normalized:
            return "CyberPanel"
        if normalized.startswith("/www/wwwlogs/"):
            return "aaPanel"
        if "nginx" in normalized:
            return "Nginx"
        if "apache" in normalized or "httpd" in normalized:
            return "Apache"
        return "Web"

    def collect(self):
        incidents = []
        candidates = [
            (self._server_name(path), path)
            for path in self.cfg.resolved_web_error_logs()
        ]
        seen = set()
        for server, path in candidates:
            if path in seen or not safe_path_exists(path):
                continue
            seen.add(path)
            lines = self.tailer.read_new_lines(
                path,
                max_lines=self.cfg.max_log_lines_per_cycle,
                max_line_chars=self.cfg.max_log_line_chars,
            )
            incident = self._analyze(server, path, lines)
            if incident:
                incidents.append(incident)
        return incidents
