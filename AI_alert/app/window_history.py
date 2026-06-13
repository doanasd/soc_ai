from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Deque, Dict, Iterable, Tuple


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    text = str(value or "").strip()
    if not text:
        return datetime.now(timezone.utc)
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalize_text(value: Any, fallback: str = "-") -> str:
    text = str(value or "").strip()
    return text or fallback


def _window_identity(
    window_start: datetime, window_end: datetime, correlation_key: str
) -> Tuple[str, str, str]:
    return (
        window_start.isoformat().replace("+00:00", "Z"),
        window_end.isoformat().replace("+00:00", "Z"),
        correlation_key,
    )


@dataclass(frozen=True)
class WindowHistoryEntry:
    correlation_key: str
    primary_target: str
    dominant_log_type: str
    window_start: datetime
    window_end: datetime
    aggregated_record_count: int
    source_ips: Tuple[str, ...]

    @property
    def identity(self) -> Tuple[str, str, str]:
        return _window_identity(self.window_start, self.window_end, self.correlation_key)


class WindowCorrelationTracker:
    """Track recent window summaries and derive short-term recurrence context."""

    def __init__(self, lookback_seconds: int, window_seconds: int) -> None:
        self._lookback_seconds = max(300, int(lookback_seconds))
        self._window_seconds = max(1, int(window_seconds))
        self._entries: Deque[WindowHistoryEntry] = deque()

    def summarize(self, window_summary: Dict[str, Any]) -> Dict[str, Any]:
        current = self._entry_from_summary(window_summary)
        self._purge(current.window_end)

        matching = [
            entry
            for entry in self._entries
            if entry.correlation_key == current.correlation_key and entry.identity != current.identity
        ]
        matching_with_current = matching + [current]

        streak_count, streak_start = self._consecutive_streak(matching_with_current, current)
        source_ips = {
            ip
            for entry in matching_with_current
            for ip in entry.source_ips
            if ip and ip != "-"
        }
        total_records = sum(entry.aggregated_record_count for entry in matching_with_current)
        matching_windows = len(matching_with_current)
        continuous_minutes = max(
            5, int((current.window_end - streak_start).total_seconds() // 60)
        )

        return {
            "lookback_seconds": self._lookback_seconds,
            "correlation_key": current.correlation_key,
            "primary_target": current.primary_target,
            "dominant_log_type": current.dominant_log_type,
            "matching_windows_last_hour": matching_windows,
            "consecutive_matching_windows": streak_count,
            "continuous_minutes": continuous_minutes,
            "aggregated_records_last_hour": total_records,
            "unique_source_ip_count_last_hour": len(source_ips),
            "severity_signal": self._severity_signal(
                matching_windows=matching_windows,
                streak_count=streak_count,
                continuous_minutes=continuous_minutes,
            ),
            "is_isolated_window": matching_windows == 1,
        }

    def record(self, window_summary: Dict[str, Any]) -> None:
        entry = self._entry_from_summary(window_summary)
        self._purge(entry.window_end)

        if any(existing.identity == entry.identity for existing in self._entries):
            return

        self._entries.append(entry)

    def _purge(self, reference_time: datetime) -> None:
        cutoff = reference_time - timedelta(seconds=self._lookback_seconds)
        while self._entries and self._entries[0].window_end < cutoff:
            self._entries.popleft()

    def _entry_from_summary(self, window_summary: Dict[str, Any]) -> WindowHistoryEntry:
        window = window_summary.get("window") or {}
        top_groups = window_summary.get("top_groups") or []
        top_group = top_groups[0] if top_groups else {}
        source_ips = tuple(
            str(row.get("ip") or "-")
            for row in (window_summary.get("top_source_ips") or [])[:20]
            if row.get("ip")
        )

        dominant_log_type = _normalize_text(window_summary.get("dominant_log_type"), "unknown")
        action = _normalize_text(top_group.get("action") or window_summary.get("dominant_action"))
        method = _normalize_text(top_group.get("method"))
        uri = _normalize_text(top_group.get("uri"))
        rule_id = _normalize_text(top_group.get("rule_id"))
        dst_ip = _normalize_text(top_group.get("dst_ip"))
        dst_port = _normalize_text(top_group.get("destination_port"))

        if "waf" in dominant_log_type.lower():
            correlation_key = "|".join(["waf", action, method, uri, rule_id])
            primary_target = f"{method} {uri}".strip()
        else:
            correlation_key = "|".join([dominant_log_type, action, dst_ip, dst_port, uri])
            primary_target = uri if uri != "-" else f"{dst_ip}:{dst_port}"

        return WindowHistoryEntry(
            correlation_key=correlation_key,
            primary_target=primary_target,
            dominant_log_type=dominant_log_type,
            window_start=_parse_timestamp(window.get("start")),
            window_end=_parse_timestamp(window.get("end")),
            aggregated_record_count=max(1, int(window.get("aggregated_record_count") or 1)),
            source_ips=source_ips,
        )

    def _consecutive_streak(
        self, entries: Iterable[WindowHistoryEntry], current: WindowHistoryEntry
    ) -> tuple[int, datetime]:
        streak = 1
        streak_start = current.window_start
        sorted_entries = sorted(entries, key=lambda entry: entry.window_start)
        previous = current

        for entry in reversed(sorted_entries[:-1]):
            gap_seconds = (previous.window_start - entry.window_end).total_seconds()
            if gap_seconds > self._window_seconds:
                break
            streak += 1
            streak_start = entry.window_start
            previous = entry

        return streak, streak_start

    @staticmethod
    def _severity_signal(
        matching_windows: int, streak_count: int, continuous_minutes: int
    ) -> str:
        if matching_windows <= 1:
            return "isolated_single_window"
        if streak_count >= 10 or continuous_minutes >= 50:
            return "near_continuous_last_hour"
        if streak_count >= 6 or continuous_minutes >= 30:
            return "sustained_multi_window"
        if streak_count >= 3 or matching_windows >= 4:
            return "recurring_multi_window"
        return "short_recurrence"


__all__ = ["WindowCorrelationTracker"]
