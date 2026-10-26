from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


class StateStore:
    def __init__(
        self,
        state_dir: Path,
        ssh_failure_tracked_ips_max: int = 1000,
        ssh_failure_persist_threshold: int = 5,
    ):
        self.state_dir = state_dir
        self.path = state_dir / "state.json"
        self.lock = threading.RLock()
        self.ssh_failure_tracked_ips_max = ssh_failure_tracked_ips_max
        self.ssh_failure_persist_threshold = ssh_failure_persist_threshold
        self._last_ssh_failure_save = 0.0
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.data: Dict[str, Any] = self._load()

    def _load(self) -> Dict[str, Any]:
        empty = {
            "files": {},
            "alerts": {},
            "health_active": {},
            "ssh_failures": {},
            "journal": {},
        }
        try:
            data = json.loads(self.path.read_text())
            if not isinstance(data, dict):
                return empty
            for key in empty:
                if not isinstance(data.get(key), dict):
                    data[key] = {}
            if not isinstance(data.get("heartbeat"), str):
                data["heartbeat"] = None
            return data
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return empty

    def save(self) -> None:
        with self.lock:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=".state-", dir=str(self.state_dir))
            try:
                with os.fdopen(fd, "w") as f:
                    json.dump(self.data, f, indent=2, sort_keys=True)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, self.path)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)

    def can_alert(self, fingerprint: str, cooldown: int) -> bool:
        now = time.time()
        with self.lock:
            try:
                last = float(self.data.setdefault("alerts", {}).get(fingerprint, 0))
            except (TypeError, ValueError):
                last = 0.0
            return now - last >= cooldown

    def mark_alert_sent(self, fingerprint: str, cooldown: int) -> None:
        with self.lock:
            now = time.time()
            alerts = self.data.setdefault("alerts", {})
            retention = max(cooldown * 2, 86400)
            self.data["alerts"] = {
                key: timestamp for key, timestamp in alerts.items()
                if _recent_timestamp(timestamp, now, retention)
            }
            self.data["alerts"][fingerprint] = now
            self.save()

    def file_cursor(self, path: str) -> Dict[str, Any]:
        return self.data.setdefault("files", {}).setdefault(path, {"inode": None, "offset": 0})

    def update_file_cursor(self, path: str, inode: int, offset: int) -> None:
        with self.lock:
            cursor = {"inode": inode, "offset": offset}
            if self.data.setdefault("files", {}).get(path) != cursor:
                self.data["files"][path] = cursor
                self.save()

    def journal_cursor(self, key: str = "kernel") -> Optional[str]:
        with self.lock:
            return self.data.setdefault("journal", {}).get(key)

    def update_journal_cursor(self, key: str, cursor: str) -> None:
        with self.lock:
            if self.data.setdefault("journal", {}).get(key) != cursor:
                self.data["journal"][key] = cursor
                self.save()

    def set_health_active(self, key: str, active: bool) -> bool:
        """Return previous active state."""
        with self.lock:
            health = self.data.setdefault("health_active", {})
            old = bool(health.get(key, False))
            active = bool(active)
            if old != active:
                health[key] = active
                self.save()
            return old

    def add_ssh_failure(self, ip: str, ts: float, window: int) -> int:
        with self.lock:
            failures = self.data.setdefault("ssh_failures", {})
            if ip not in failures and len(failures) >= self.ssh_failure_tracked_ips_max:
                oldest_ip = min(
                    failures,
                    key=lambda key: _latest_timestamp(failures[key]),
                )
                failures.pop(oldest_ip, None)
            previous = failures.get(ip, [])
            if not isinstance(previous, list):
                previous = []
            arr = [float(x) for x in previous if _recent_timestamp(x, ts, window)]
            arr.append(ts)
            failures[ip] = arr
            count = len(arr)
            if (
                count == 1
                or count == self.ssh_failure_persist_threshold
                or time.monotonic() - self._last_ssh_failure_save >= 15
            ):
                self.save()
                self._last_ssh_failure_save = time.monotonic()
            return count

    def clear_ssh_failures(self, ip: str) -> None:
        with self.lock:
            failures = self.data.setdefault("ssh_failures", {})
            if ip in failures:
                failures.pop(ip)
                self.save()

    def heartbeat(self) -> Optional[str]:
        with self.lock:
            value = self.data.get("heartbeat")
            return value if isinstance(value, str) else None

    def set_heartbeat(self, timestamp: Optional[str] = None) -> None:
        with self.lock:
            value = timestamp or datetime.now(timezone.utc).isoformat()
            if self.data.get("heartbeat") != value:
                self.data["heartbeat"] = value
                self.save()


def _recent_timestamp(value: Any, now: float, retention: float) -> bool:
    try:
        return now - float(value) <= retention
    except (TypeError, ValueError):
        return False


def _latest_timestamp(values: Any) -> float:
    if not isinstance(values, list):
        return 0.0
    timestamps = []
    for value in values:
        try:
            timestamps.append(float(value))
        except (TypeError, ValueError):
            pass
    return max(timestamps, default=0.0)
