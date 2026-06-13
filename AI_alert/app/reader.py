from __future__ import annotations

import io
import json
import logging
import os
import time
from pathlib import Path
from typing import Dict, Generator, Optional

from .models import Event

logger = logging.getLogger(__name__)


class LogFollower:
    """Follow a JSON lines log file similar to `tail -F`.

    Handles file rotation and partial writes. Each yielded value is a validated
    `Event` instance constructed from one JSON object per line.
    """

    def __init__(
        self,
        path: Path,
        poll_interval: float = 1.0,
        start_position: str = "end",
    ) -> None:
        self._path = path
        self._poll_interval = poll_interval
        self._start_position = "beginning" if start_position == "beginning" else "end"

    def _open(self) -> Optional[io.TextIOWrapper]:
        try:
            return self._path.open("r", encoding="utf-8")
        except FileNotFoundError:
            logger.warning("Log file %s not found. Waiting for creation.", self._path)
            return None

    def _stat_inode(self) -> Optional[int]:
        try:
            return os.stat(self._path).st_ino
        except FileNotFoundError:
            return None

    def entries(self) -> Generator[Optional[Event], None, None]:
        """Yield `Event` instances, or `None` on idle polling ticks."""

        current_inode: Optional[int] = None
        fh: Optional[io.TextIOWrapper] = None
        buffer = ""
        first_open = True

        while True:
            if fh is None:
                fh = self._open()
                if fh is not None:
                    current_inode = self._stat_inode()
                    if first_open and self._start_position == "end":
                        fh.seek(0, io.SEEK_END)
                    else:
                        fh.seek(0, io.SEEK_SET)
                    first_open = False

            if fh is None:
                time.sleep(self._poll_interval)
                yield None
                continue

            line = fh.readline()
            if not line:
                # Detect rotation
                inode = self._stat_inode()
                if inode is not None and current_inode is not None and inode != current_inode:
                    logger.info("Detected log rotation for %s", self._path)
                    fh.close()
                    fh = None
                    buffer = ""
                    continue

                try:
                    current_pos = fh.tell()
                    file_size = fh.seek(0, io.SEEK_END)
                    fh.seek(current_pos, io.SEEK_SET)
                except OSError:
                    file_size = None
                    current_pos = None

                if (
                    file_size is not None
                    and current_pos is not None
                    and file_size < current_pos
                ):
                    logger.info("Detected log truncation for %s; seeking to beginning.", self._path)
                    fh.seek(0, io.SEEK_SET)
                    buffer = ""
                    continue

                time.sleep(self._poll_interval)
                yield None
                continue

            buffer += line
            if not buffer.endswith("\n"):
                # partial line, wait for completion
                continue

            raw_line = buffer.strip()
            buffer = ""
            if not raw_line:
                continue

            try:
                obj: Dict[str, object] = json.loads(raw_line)
                event = Event.model_validate(obj)
            except json.JSONDecodeError:
                logger.exception("Skipping invalid JSON line: %s", raw_line)
                continue
            except Exception:
                logger.exception("Failed to validate event. Skipping line.")
                continue

            yield event

    def events(self) -> Generator[Event, None, None]:
        """Backward-compatible event-only iterator."""

        for entry in self.entries():
            if entry is not None:
                yield entry


__all__ = ["LogFollower"]
