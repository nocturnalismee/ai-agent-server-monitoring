from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class IncidentSpool:
    """Durable, best-effort storage for incidents that could not be delivered."""

    def __init__(
        self,
        state_dir: Path,
        max_entries: int = 200,
        max_attempts: int = 5,
        logger=None,
    ):
        self.state_dir = Path(state_dir)
        self.directory = self.state_dir / "spool"
        self.max_entries = max(0, int(max_entries))
        self.max_attempts = max(1, int(max_attempts))
        self.log = logger
        self._lock = threading.RLock()
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
        except OSError:
            self._debug("Failed to create spool directory", exc_info=True)

    @staticmethod
    def key_for(fingerprint: Any) -> str:
        return hashlib.sha256(str(fingerprint).encode("utf-8")).hexdigest()[:16]

    def _path(self, key: str) -> Path:
        return self.directory / f"{key}.json"

    def _debug(self, message: str, *args, **kwargs) -> None:
        debug = getattr(self.log, "debug", None)
        if debug is None:
            return
        try:
            debug(message, *args, **kwargs)
        except Exception:
            pass

    def _remove_path(self, path: Path) -> None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            self._debug("Failed to remove spool entry: %s", path, exc_info=True)

    def _write(self, key: str, data: Dict[str, Any]) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".spool-", dir=str(self.directory))
        try:
            with os.fdopen(fd, "w") as handle:
                json.dump(data, handle, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self._path(key))
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def _read(self, path: Path) -> Optional[Dict[str, Any]]:
        try:
            data = json.loads(path.read_text())
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            self._remove_path(path)
            return None
        if not isinstance(data, dict) or not isinstance(data.get("incident"), dict):
            self._remove_path(path)
            return None
        try:
            data["attempts"] = int(data.get("attempts", 0))
            data["created_at"] = float(data.get("created_at", 0))
            data["next_attempt_at"] = float(data.get("next_attempt_at", 0))
        except (TypeError, ValueError):
            self._remove_path(path)
            return None
        return data

    def _paths(self) -> List[Path]:
        try:
            return sorted(self.directory.glob("*.json"))
        except OSError:
            self._debug("Failed to list spool directory", exc_info=True)
            return []

    def add(self, incident) -> None:
        with self._lock:
            try:
                now = time.time()
                payload = {
                    "incident": incident.as_dict(),
                    "attempts": 0,
                    "created_at": now,
                    "next_attempt_at": now,
                }
                self._write(self.key_for(incident.fingerprint), payload)
                self._evict()
            except Exception:
                self._debug("Failed to spool incident", exc_info=True)

    def due(self, now: Optional[float] = None) -> List[Tuple[str, Dict[str, Any], int]]:
        with self._lock:
            current = time.time() if now is None else float(now)
            entries = []
            for path in self._paths():
                data = self._read(path)
                if data is None:
                    continue
                if data["next_attempt_at"] <= current:
                    entries.append(
                        (
                            data["next_attempt_at"],
                            path.stem,
                            data["incident"],
                            data["attempts"],
                        )
                    )
            entries.sort(key=lambda entry: (entry[0], entry[1]))
            return [
                (key, incident, attempts)
                for _, key, incident, attempts in entries
            ]

    def mark_attempt(self, key: str) -> None:
        with self._lock:
            path = self._path(key)
            data = self._read(path)
            if data is None:
                return
            attempts = data["attempts"] + 1
            if attempts >= self.max_attempts:
                self._remove_path(path)
                return
            delay = min(300, 30 * (2 ** min(attempts, 16)))
            data["attempts"] = attempts
            data["next_attempt_at"] = time.time() + delay
            try:
                self._write(key, data)
            except Exception:
                self._debug("Failed to update spool entry: %s", key, exc_info=True)

    def remove(self, key: str) -> None:
        with self._lock:
            self._remove_path(self._path(key))

    def _evict(self) -> None:
        entries = []
        for path in self._paths():
            data = self._read(path)
            if data is None:
                continue
            entries.append((data["created_at"], path.name, path))
        overflow = len(entries) - self.max_entries
        if overflow <= 0:
            return
        entries.sort(key=lambda entry: (entry[0], entry[1]))
        for _, _, path in entries[:overflow]:
            self._remove_path(path)
