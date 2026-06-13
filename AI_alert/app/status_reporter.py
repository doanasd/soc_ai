from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from .batching import WindowBatch, build_window_summary
from .models import ModelUsage


class NoAlertStatusReporter:
    """Track non-alert activity and emit periodic health summaries."""

    def __init__(self, interval_seconds: int) -> None:
        self._interval_seconds = interval_seconds
        self.reset()

    def reset(self, now: datetime | None = None) -> None:
        self._period_start = now or datetime.now(timezone.utc)
        self._batches_analyzed = 0
        self._event_count = 0
        self._aggregated_record_count = 0
        self._log_type_counts: Counter[str] = Counter()
        self._action_counts: Counter[str] = Counter()
        self._source_counts: Counter[str] = Counter()
        self._destination_counts: Counter[str] = Counter()
        self._llm_calls = 0
        self._llm_prompt_tokens = 0
        self._llm_cached_tokens = 0
        self._llm_completion_tokens = 0
        self._llm_total_tokens = 0
        self._llm_total_cost_usd = 0.0

    def record_batch(self, batch: WindowBatch, usage: ModelUsage | None = None) -> None:
        summary = build_window_summary(
            batch,
            configured_window_seconds=int(
                max(1, (batch.window_end - batch.window_start).total_seconds())
            ),
        )
        self._batches_analyzed += 1
        window = summary["window"]
        self._event_count += int(window.get("event_count", 0))
        self._aggregated_record_count += int(window.get("aggregated_record_count", 0))

        for key, value in summary.get("log_type_counts", {}).items():
            self._log_type_counts[str(key)] += int(value)
        for key, value in summary.get("action_counts", {}).items():
            self._action_counts[str(key)] += int(value)
        for row in summary.get("top_source_ips", []):
            ip = row.get("ip")
            count = row.get("count", 0)
            if ip:
                self._source_counts[str(ip)] += int(count)
        for row in summary.get("top_destination_ips", []):
            ip = row.get("ip")
            count = row.get("count", 0)
            if ip:
                self._destination_counts[str(ip)] += int(count)

        if usage is not None:
            self._llm_calls += int(usage.attempts)
            self._llm_prompt_tokens += int(usage.prompt_tokens)
            self._llm_cached_tokens += int(usage.cached_tokens)
            self._llm_completion_tokens += int(usage.completion_tokens)
            self._llm_total_tokens += int(usage.total_tokens)
            self._llm_total_cost_usd += float(usage.total_cost_usd)

    def record_alert(self, now: datetime | None = None) -> None:
        self.reset(now=now)

    def should_send(self, now: datetime | None = None) -> bool:
        if self._interval_seconds <= 0:
            return False
        current_time = now or datetime.now(timezone.utc)
        return current_time >= self._period_start + timedelta(
            seconds=self._interval_seconds
        )

    def build_summary(self, now: datetime | None = None) -> Dict[str, Any]:
        current_time = now or datetime.now(timezone.utc)
        return {
            "period": {
                "start": self._period_start.isoformat().replace("+00:00", "Z"),
                "end": current_time.isoformat().replace("+00:00", "Z"),
                "interval_seconds": self._interval_seconds,
            },
            "alert_count": 0,
            "batches_analyzed": self._batches_analyzed,
            "event_count": self._event_count,
            "aggregated_record_count": self._aggregated_record_count,
            "log_type_counts": dict(self._log_type_counts.most_common()),
            "action_counts": dict(self._action_counts.most_common()),
            "top_source_ips": [
                {"ip": ip, "count": count}
                for ip, count in self._source_counts.most_common(5)
            ],
            "top_destination_ips": [
                {"ip": ip, "count": count}
                for ip, count in self._destination_counts.most_common(5)
            ],
            "llm_usage": {
                "calls": self._llm_calls,
                "prompt_tokens": self._llm_prompt_tokens,
                "cached_tokens": self._llm_cached_tokens,
                "completion_tokens": self._llm_completion_tokens,
                "total_tokens": self._llm_total_tokens,
                "total_cost_usd": self._llm_total_cost_usd,
            },
        }


__all__ = ["NoAlertStatusReporter"]
