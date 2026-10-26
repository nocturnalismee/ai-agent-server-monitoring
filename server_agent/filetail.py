from __future__ import annotations

import os
from pathlib import Path
from typing import List

from .state import StateStore


def safe_path_exists(path_str: str) -> bool:
    """Check path existence safely, suppressing PermissionError (e.g. Python 3.12+ parent traversal)."""
    if not path_str:
        return False
    try:
        return os.path.exists(path_str)
    except (PermissionError, OSError):
        return False


class FileTailer:
    """Incrementally read appended log lines and survive truncation/rotation."""

    def __init__(self, state: StateStore, logger):
        self.state = state
        self.logger = logger

    def read_new_lines(
        self,
        path_str: str,
        first_start_at_end: bool = True,
        max_lines: int = 250,
        max_line_chars: int = 4096,
    ) -> List[str]:
        path = Path(path_str)
        try:
            st = path.stat()
        except (FileNotFoundError, PermissionError, OSError) as exc:
            self.logger.debug("Cannot inspect %s: %s", path, exc)
            return []

        cursor = self.state.file_cursor(str(path))
        old_inode = cursor.get("inode")
        old_offset = int(cursor.get("offset", 0))

        # First observation: start at EOF so install doesn't alert on old historical events.
        if old_inode is None:
            offset = st.st_size if first_start_at_end else 0
        # Rotation or truncation.
        elif old_inode != st.st_ino or st.st_size < old_offset:
            offset = 0
        else:
            offset = old_offset

        lines = []
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                f.seek(offset)
                for _ in range(max_lines):
                    line = self._read_bounded_line(f, max_line_chars)
                    if not line:
                        break
                    lines.append(line)
                new_offset = f.tell()
            self.state.update_file_cursor(str(path), st.st_ino, new_offset)
        except (PermissionError, OSError) as exc:
            self.logger.warning("Cannot read %s: %s", path, exc)
        return lines

    @staticmethod
    def _read_bounded_line(file_obj, max_line_chars: int) -> str:
        """Read one physical line without retaining unbounded attacker-controlled data."""
        line = file_obj.readline(max_line_chars + 1)
        if not line or line.endswith("\n") or len(line) <= max_line_chars:
            return line

        # readline(limit) stops before a newline for oversized entries. Consume
        # the remainder so the next cycle starts at the following physical line.
        while True:
            remainder = file_obj.readline(max_line_chars + 1)
            if not remainder or remainder.endswith("\n"):
                break
        return line[:max_line_chars] + " [truncated]\n"
