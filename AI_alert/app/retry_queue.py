from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .batching import WindowBatch, window_batch_from_dict, window_batch_to_dict


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _isoformat(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(slots=True)
class RetryItem:
    item_id: str
    batch: WindowBatch
    attempts: int
    available_at: datetime
    last_error: str
    enqueued_at: datetime


class FailedBatchQueue:
    """Persistent single-process retry queue for failed analysis batches."""

    def __init__(
        self,
        path: Path,
        base_delay_seconds: int,
        max_delay_seconds: int,
        max_attempts: int,
    ) -> None:
        self._path = path
        self._base_delay_seconds = max(1, base_delay_seconds)
        self._max_delay_seconds = max(self._base_delay_seconds, max_delay_seconds)
        self._max_attempts = max(1, max_attempts)
        self._items: List[Dict[str, Any]] = []
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            self._items = []
            return

        items: List[Dict[str, Any]] = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        self._items = items

    def _persist(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        lines = [json.dumps(item, ensure_ascii=False) for item in self._items]
        self._path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    def _serialize_item(
        self,
        batch: WindowBatch,
        attempts: int,
        available_at: datetime,
        last_error: str,
        item_id: Optional[str] = None,
        enqueued_at: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        return {
            "id": item_id or str(uuid.uuid4()),
            "attempts": attempts,
            "available_at": _isoformat(available_at),
            "last_error": last_error,
            "enqueued_at": _isoformat(enqueued_at or _utcnow()),
            "batch": window_batch_to_dict(batch),
        }

    def size(self) -> int:
        return len(self._items)

    def enqueue(self, batch: WindowBatch, reason: str) -> None:
        item = self._serialize_item(
            batch=batch,
            attempts=0,
            available_at=_utcnow(),
            last_error=reason,
        )
        self._items.append(item)
        self._persist()

    def pop_due(self, now: Optional[datetime] = None) -> Optional[RetryItem]:
        current_time = now or _utcnow()
        due_index: Optional[int] = None
        due_at: Optional[datetime] = None

        for index, item in enumerate(self._items):
            available_at = datetime.fromisoformat(str(item["available_at"]).replace("Z", "+00:00"))
            if available_at <= current_time and (due_at is None or available_at < due_at):
                due_index = index
                due_at = available_at

        if due_index is None:
            return None

        raw = self._items.pop(due_index)
        self._persist()
        return RetryItem(
            item_id=str(raw["id"]),
            batch=window_batch_from_dict(dict(raw["batch"])),
            attempts=int(raw.get("attempts", 0)),
            available_at=datetime.fromisoformat(str(raw["available_at"]).replace("Z", "+00:00")),
            last_error=str(raw.get("last_error") or ""),
            enqueued_at=datetime.fromisoformat(str(raw["enqueued_at"]).replace("Z", "+00:00")),
        )

    def requeue(self, item: RetryItem, reason: str, now: Optional[datetime] = None) -> bool:
        current_time = now or _utcnow()
        next_attempt = item.attempts + 1
        if next_attempt >= self._max_attempts:
            return False

        delay = min(self._max_delay_seconds, self._base_delay_seconds * (2 ** item.attempts))
        serialized = self._serialize_item(
            batch=item.batch,
            attempts=next_attempt,
            available_at=current_time + timedelta(seconds=delay),
            last_error=reason,
            item_id=item.item_id,
            enqueued_at=item.enqueued_at,
        )
        self._items.append(serialized)
        self._persist()
        return True


__all__ = ["FailedBatchQueue", "RetryItem"]
