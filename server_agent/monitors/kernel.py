from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import List, Optional, Set

from ..filetail import safe_path_exists
from ..models import Incident

OOM_KILL_RE = re.compile(
    r"(?:Out of memory|Memory cgroup out of memory).*?Kill(?:ed)?\s+process\s+(?P<pid>\d+)\s+\((?P<process>[^)]+)\)",
    re.I,
)
OOM_GENERIC_KILL_RE = re.compile(
    r"\bKilled process\s+(?P<pid>\d+)\s+\((?P<process>[^)]+)\)",
    re.I,
)
OOM_REAPED_RE = re.compile(
    r"oom_reaper:\s+reaped\s+process\s+(?P<pid>\d+)\s+\((?P<process>[^)]+)\)",
    re.I,
)
OOM_INVOKED_RE = re.compile(
    r"\b(?:invoked oom-killer|Out of memory: Kill process|oom-killer:\s+gfp_mask)\b",
    re.I,
)

KERNEL_CRASH_RE = re.compile(
    r"(?P<type>Kernel panic - not syncing|BUG: unable to handle kernel|kernel BUG at|general protection fault|Internal error: Oops|kernel:\s+Oops:\s+\d+)",
    re.I,
)


class KernelMonitor:
    """Monitors Linux kernel and system logs for OOM killer executions and kernel crashes."""

    def __init__(self, config, state, tailer, logger):
        self.cfg = config
        self.state = state
        self.tailer = tailer
        self.logger = logger

    def _sample(self, line: str) -> str:
        line = line.rstrip()
        if len(line) <= self.cfg.max_log_sample_chars:
            return line
        return line[: self.cfg.max_log_sample_chars - 14] + " [truncated]"

    def _parse_line(self, line: str, source: str, seen: Set[str]) -> Optional[Incident]:
        oom_match = OOM_KILL_RE.search(line) or OOM_GENERIC_KILL_RE.search(line) or OOM_REAPED_RE.search(line)
        if oom_match:
            pid = oom_match.group("pid")
            process = oom_match.group("process")
            dedup_key = f"oom:{process}"
            if dedup_key in seen:
                return None
            seen.add(dedup_key)
            return Incident(
                kind="oom",
                severity="CRITICAL",
                title=f"OOM killer terminated {process} (PID {pid})",
                summary=(
                    f"Linux Out-Of-Memory (OOM) killer terminated process '{process}' (PID {pid}) "
                    "due to host memory exhaustion."
                ),
                fingerprint=f"oom:{process}",
                details={
                    "process": process,
                    "pid": pid,
                    "source": source,
                    "raw_log": self._sample(line),
                },
            )

        if OOM_INVOKED_RE.search(line):
            dedup_key = "oom:invoked"
            if dedup_key in seen:
                return None
            seen.add(dedup_key)
            return Incident(
                kind="oom",
                severity="CRITICAL",
                title="OOM killer invoked by kernel",
                summary="Linux kernel invoked Out-Of-Memory (OOM) killer due to memory exhaustion.",
                fingerprint="oom:invoked",
                details={
                    "source": source,
                    "raw_log": self._sample(line),
                },
            )

        crash_match = KERNEL_CRASH_RE.search(line)
        if crash_match:
            raw_type = crash_match.group("type").strip()
            type_slug = re.sub(r"[^a-zA-Z0-9]+", "_", raw_type.lower())[:32]
            dedup_key = f"kernel_crash:{type_slug}"
            if dedup_key in seen:
                return None
            seen.add(dedup_key)
            return Incident(
                kind="kernel_crash",
                severity="CRITICAL",
                title=f"Kernel crash/panic: {raw_type}",
                summary=f"Linux kernel reported a critical fault or panic: {raw_type}",
                fingerprint=f"kernel:crash:{type_slug}",
                details={
                    "error_type": raw_type,
                    "source": source,
                    "raw_log": self._sample(line),
                },
            )

        return None

    def _read_from_files(self) -> List[tuple[str, str]]:
        """Read newly appended lines from available kernel log files."""
        records: List[tuple[str, str]] = []
        for path_str in self.cfg.resolved_kernel_logs():
            if not safe_path_exists(path_str):
                continue
            lines = self.tailer.read_new_lines(
                path_str,
                max_lines=self.cfg.max_log_lines_per_cycle,
                max_line_chars=self.cfg.max_log_line_chars,
            )
            for line in lines:
                records.append((path_str, line))
        return records

    def _read_from_journal(self) -> List[tuple[str, str]]:
        """Fallback to journalctl -k if no traditional log files are present."""
        cursor = self.state.journal_cursor("kernel")
        cmd = ["journalctl", "-k", "--show-cursor", "-o", "short-iso"]
        if cursor is None:
            cmd.extend(["-n", "0"])
        else:
            cmd.extend(["--after-cursor", cursor, "-n", str(self.cfg.max_log_lines_per_cycle)])

        try:
            p = subprocess.run(
                cmd, capture_output=True, text=True, timeout=5, check=False
            )
            if p.returncode != 0:
                return []
            lines: List[tuple[str, str]] = []
            new_cursor = None
            for raw_line in p.stdout.splitlines():
                stripped = raw_line.strip()
                if stripped.startswith("-- cursor:"):
                    new_cursor = stripped.split(":", 1)[1].strip()
                elif stripped and not stripped.startswith("-- Logs begin"):
                    lines.append(("journalctl -k", raw_line[: self.cfg.max_log_line_chars]))
            if new_cursor:
                self.state.update_journal_cursor("kernel", new_cursor)
            return lines
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError, PermissionError) as exc:
            self.logger.debug("Journalctl kernel inspection skipped: %s", exc)
            return []

    def collect(self) -> List[Incident]:
        if not self.cfg.kernel_monitor_enabled:
            return []

        entries = self._read_from_files()
        if not entries and self.cfg.kernel_journal_fallback:
            # Fall back to journald if no physical kernel log files are present
            any_file_exists = any(safe_path_exists(p) for p in self.cfg.resolved_kernel_logs())
            if not any_file_exists:
                entries = self._read_from_journal()

        incidents: List[Incident] = []
        seen_in_batch: Set[str] = set()
        for source, line in entries:
            incident = self._parse_line(line, source, seen_in_batch)
            if incident:
                incidents.append(incident)
        return incidents
