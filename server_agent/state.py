from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict


class StateStore:
    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.path = state_dir / "state.json"
        self.lock = threading.RLock()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.data: Dict[str, Any] = self._load()

    def _load(self) -> Dict[str, Any]:
        try:
            data = json.loads(self.path.read_text())
            return data if isinstance(data, dict) else {"files": {}, "alerts": {}, "health_active": {}, "ssh_failures": {}}
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {"files": {}, "alerts": {}, "health_active": {}, "ssh_failures": {}}

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
            last = float(self.data.setdefault("alerts", {}).get(fingerprint, 0))
            return now - last >= cooldown

    def mark_alert_sent(self, fingerprint: str) -> None:
        with self.lock:
            self.data.setdefault("alerts", {})[fingerprint] = time.time()
            self.save()

    def file_cursor(self, path: str) -> Dict[str, Any]:
        return self.data.setdefault("files", {}).setdefault(path, {"inode": None, "offset": 0})

    def update_file_cursor(self, path: str, inode: int, offset: int) -> None:
        with self.lock:
            cursor = {"inode": inode, "offset": offset}
            if self.data.setdefault("files", {}).get(path) != cursor:
                self.data["files"][path] = cursor
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
            arr = [float(x) for x in failures.get(ip, []) if ts - float(x) <= window]
            arr.append(ts)
            failures[ip] = arr
            self.save()
            return len(arr)

    def clear_ssh_failures(self, ip: str) -> None:
        with self.lock:
            failures = self.data.setdefault("ssh_failures", {})
            if ip in failures:
                failures.pop(ip)
                self.save()
