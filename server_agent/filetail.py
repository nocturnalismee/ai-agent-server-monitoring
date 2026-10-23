from __future__ import annotations

import os
from pathlib import Path
from typing import List

from .state import StateStore


class FileTailer:
    """Incrementally read appended log lines and survive truncation/rotation."""

    def __init__(self, state: StateStore, logger):
        self.state = state
        self.logger = logger

    def read_new_lines(
        self, path_str: str, first_start_at_end: bool = True, max_lines: int = 500
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
                    line = f.readline()
                    if not line:
                        break
                    lines.append(line)
                new_offset = f.tell()
            self.state.update_file_cursor(str(path), st.st_ino, new_offset)
        except (PermissionError, OSError) as exc:
            self.logger.warning("Cannot read %s: %s", path, exc)
        return lines
