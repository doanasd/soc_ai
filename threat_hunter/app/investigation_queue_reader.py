"""
Investigation Queue Reader — consumes investigation requests from AI Alert.

Watches the shared JSONL queue file (pending_investigations.jsonl) for new
requests written by AI Alert. Supports both polling and batch consumption.
"""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class InvestigationQueueReader:
    """
    Reads investigation requests from the shared JSONL queue file.

    Uses file offset tracking to only read new entries since the last poll.
    Marks consumed entries by rewriting the file without them (or via offset).
    """

    def __init__(self, queue_path: Path, poll_interval: float = 5.0) -> None:
        self._queue_path = queue_path
        self._poll_interval = poll_interval
        self._offset_file = queue_path.parent / ".investigation_queue_offset"
        self._last_offset: int = self._load_offset()

    def _load_offset(self) -> int:
        """Load the last read offset from disk."""
        try:
            if self._offset_file.exists():
                return int(self._offset_file.read_text().strip())
        except (ValueError, OSError):
            pass
        return 0

    def _save_offset(self, offset: int) -> None:
        """Persist the current read offset to disk."""
        try:
            self._offset_file.parent.mkdir(parents=True, exist_ok=True)
            self._offset_file.write_text(str(offset))
        except OSError:
            logger.exception("Failed to save queue offset")

    def poll(self) -> List[Dict[str, Any]]:
        """
        Poll the queue file for new investigation requests.

        Returns a list of new requests since the last poll.
        Updates the offset so the same requests are not returned again.
        """
        if not self._queue_path.exists():
            return []

        requests: List[Dict[str, Any]] = []
        try:
            file_size = self._queue_path.stat().st_size

            # Handle file truncation (e.g., manual cleanup)
            if file_size < self._last_offset:
                logger.info(
                    "Queue file truncated (size %d < offset %d). Resetting offset.",
                    file_size, self._last_offset,
                )
                self._last_offset = 0

            if file_size <= self._last_offset:
                return []

            with self._queue_path.open("r", encoding="utf-8") as fh:
                fh.seek(self._last_offset)
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        if isinstance(data, dict) and data.get("type") == "alert_investigation":
                            requests.append(data)
                    except json.JSONDecodeError:
                        logger.warning("Skipping malformed queue entry: %s", line[:100])

                new_offset = fh.tell()

            # Always advance the offset to prevent re-reading already-processed lines,
            # even if no valid alert_investigation entries were found (e.g. skipped/malformed).
            if new_offset > self._last_offset:
                self._last_offset = new_offset
                self._save_offset(new_offset)

            if requests:
                logger.info(
                    "Read %d new investigation request(s) from queue.", len(requests),
                )

        except OSError:
            logger.exception("Error reading investigation queue at %s", self._queue_path)

        return requests

    def wait_for_requests(self, timeout: float = 30.0) -> List[Dict[str, Any]]:
        """
        Block until new requests appear or timeout is reached.

        Returns the list of new requests (may be empty on timeout).
        """
        elapsed = 0.0
        while elapsed < timeout:
            requests = self.poll()
            if requests:
                return requests
            time.sleep(self._poll_interval)
            elapsed += self._poll_interval
        return []


__all__ = ["InvestigationQueueReader"]
