from __future__ import annotations

import logging
import time
from typing import Dict, Optional

from .analyzer import Analyzer
from .batching import WindowBatch, build_window_summary, representative_event_for_batch
from .config import AppConfig
from .models import Alert, BatchAnalysisResult, Event
from .window_history import WindowCorrelationTracker

logger = logging.getLogger(__name__)


class AlertEngine:
    """Apply local suppression and orchestrate alert generation."""

    def __init__(self, config: AppConfig, analyzer: Analyzer) -> None:
        self._config = config
        self._analyzer = analyzer
        self._suppression: Dict[str, float] = {}
        self._history = WindowCorrelationTracker(
            lookback_seconds=config.correlation_lookback_seconds,
            window_seconds=config.batch_window_seconds,
        )

    def _is_suppressed(self, dedup_key: str) -> bool:
        if not dedup_key:
            return False
        now = time.time()
        ttl = self._config.alert_suppression_ttl_seconds
        last = self._suppression.get(dedup_key)
        if last is None:
            return False
        if now - last > ttl:
            # expired
            del self._suppression[dedup_key]
            return False
        return True

    def _mark_emitted(self, dedup_key: str) -> None:
        if not dedup_key:
            return
        self._suppression[dedup_key] = time.time()

    def process_batch(self, batch: WindowBatch) -> BatchAnalysisResult:
        """Run the analyzer for a full window and enforce deduplication TTL."""

        representative_event = representative_event_for_batch(batch)
        window_summary = build_window_summary(
            batch, configured_window_seconds=self._config.batch_window_seconds
        )
        window_summary["historical_correlation"] = self._history.summarize(window_summary)

        result = self._analyzer.analyze_window_summary(window_summary, representative_event)
        if result.outcome != "error":
            self._history.record(window_summary)

        alert = result.alert
        if alert is None:
            return result

        dedup_key = alert.analysis.dedup_key
        if self._is_suppressed(dedup_key):
            logger.info("Suppressing duplicate alert for key %s", dedup_key)
            return BatchAnalysisResult(
                outcome="no_alert",
                alert=None,
                usage=result.usage,
                daily_totals=result.daily_totals,
            )

        self._mark_emitted(dedup_key)
        return result

    def process_event(self, event: Event) -> BatchAnalysisResult:
        """Backward-compatible wrapper for single-event processing."""

        from datetime import datetime, timedelta, timezone

        observed_at = datetime.now(timezone.utc)
        return self.process_batch(
            WindowBatch(
                events=[event],
                window_start=observed_at,
                window_end=observed_at + timedelta(seconds=1),
                first_observed_at=observed_at,
                last_observed_at=observed_at,
                flush_reason="single_event",
            )
        )


__all__ = ["AlertEngine"]
