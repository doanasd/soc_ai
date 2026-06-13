from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import HuntConfig
from .models import BaselineMetrics, HuntDataset

logger = logging.getLogger(__name__)


class BaselineTracker:
    """
    Tracks rolling baselines and detects anomalies by comparing
    the current HuntDataset against historical averages.

    The baseline is persisted to disk as JSON so it survives restarts.
    """

    # Anomaly thresholds
    VOLUME_SPIKE_THRESHOLD = 2.0    # 2x above average = spike
    VOLUME_DROP_THRESHOLD = 0.3     # 30% of average = suspicious drop
    NEW_IP_THRESHOLD = 10           # More than N completely new high-volume IPs
    MAX_HISTORY_ENTRIES = 14        # Keep ~2 weeks of daily snapshots

    def __init__(self, config: HuntConfig) -> None:
        self._config = config
        self._baseline_path = config.baseline_path
        self._baseline = self._load_baseline()

    def _load_baseline(self) -> BaselineMetrics:
        """Load baseline from disk or create empty."""
        if self._baseline_path.exists():
            try:
                data = json.loads(self._baseline_path.read_text(encoding="utf-8"))
                return BaselineMetrics.model_validate(data)
            except Exception:
                logger.exception("Failed to load baseline from %s", self._baseline_path)
        return BaselineMetrics()

    def _save_baseline(self) -> None:
        """Persist baseline to disk."""
        try:
            self._baseline_path.parent.mkdir(parents=True, exist_ok=True)
            self._baseline_path.write_text(
                self._baseline.model_dump_json(indent=2),
                encoding="utf-8",
            )
        except Exception:
            logger.exception("Failed to save baseline to %s", self._baseline_path)

    def update_baseline(self, dataset: HuntDataset) -> None:
        """
        Add the current dataset snapshot to the rolling baseline history
        and recompute averages.
        """
        snapshot = {
            "collected_at": dataset.collected_at.isoformat(),
            "total_logs": dataset.total_logs,
            "log_type_counts": dataset.log_type_counts,
            "action_counts": dataset.action_counts,
            "unique_source_ips": dataset.unique_source_ips,
            "top_source_ip_max_volume": (
                dataset.top_source_ips[0].count if dataset.top_source_ips else 0
            ),
        }

        self._baseline.history.append(snapshot)

        # Trim to max history
        if len(self._baseline.history) > self.MAX_HISTORY_ENTRIES:
            self._baseline.history = self._baseline.history[-self.MAX_HISTORY_ENTRIES:]

        # Recompute averages
        self._recompute_averages()
        self._save_baseline()

        logger.info(
            "Baseline updated: %d entries, avg_total=%.0f",
            len(self._baseline.history),
            self._baseline.avg_total_logs,
        )

    def _recompute_averages(self) -> None:
        """Recompute rolling averages from history."""
        history = self._baseline.history
        n = len(history)
        if n == 0:
            return

        self._baseline.days_of_data = n

        # Average total logs
        self._baseline.avg_total_logs = sum(
            h.get("total_logs", 0) for h in history
        ) / n

        # Average log type counts
        all_types: Dict[str, List[int]] = {}
        for h in history:
            for lt, count in h.get("log_type_counts", {}).items():
                all_types.setdefault(lt, []).append(count)
        self._baseline.avg_log_type_counts = {
            lt: sum(counts) / n for lt, counts in all_types.items()
        }

        # Average action counts
        all_actions: Dict[str, List[int]] = {}
        for h in history:
            for action, count in h.get("action_counts", {}).items():
                all_actions.setdefault(action, []).append(count)
        self._baseline.avg_action_counts = {
            action: sum(counts) / n for action, counts in all_actions.items()
        }

        # Average top source IP volume
        self._baseline.avg_top_source_ip_volume = sum(
            h.get("top_source_ip_max_volume", 0) for h in history
        ) / n

    def detect_anomalies(self, dataset: HuntDataset) -> List[Dict[str, Any]]:
        """
        Compare the current dataset against the baseline and return
        a list of anomaly dicts describing deviations.

        Each anomaly: {
            "type": "volume_spike" | "volume_drop" | "new_high_volume_ips" | "log_type_spike" | ...,
            "severity": "low" | "medium" | "high",
            "description": "...",
            "details": { ... }
        }
        """
        anomalies: List[Dict[str, Any]] = []

        if not self._baseline.history or self._baseline.avg_total_logs == 0:
            logger.info("Baseline has insufficient history (%d entries), skipping anomaly detection.",
                        len(self._baseline.history))
            return anomalies

        avg_total = self._baseline.avg_total_logs

        # ── 1. Overall volume spike / drop ───────────────────────────────────
        if avg_total > 0:
            ratio = dataset.total_logs / avg_total

            if ratio >= self.VOLUME_SPIKE_THRESHOLD:
                anomalies.append({
                    "type": "volume_spike",
                    "severity": "high" if ratio >= 3.0 else "medium",
                    "description": (
                        f"Total log volume is {ratio:.1f}x the baseline average "
                        f"({dataset.total_logs:,} vs avg {avg_total:,.0f})"
                    ),
                    "details": {
                        "current": dataset.total_logs,
                        "average": avg_total,
                        "ratio": round(ratio, 2),
                    },
                })
            elif ratio <= self.VOLUME_DROP_THRESHOLD:
                anomalies.append({
                    "type": "volume_drop",
                    "severity": "medium",
                    "description": (
                        f"Total log volume dropped to {ratio:.1%} of baseline "
                        f"({dataset.total_logs:,} vs avg {avg_total:,.0f}). "
                        f"Possible logging outage."
                    ),
                    "details": {
                        "current": dataset.total_logs,
                        "average": avg_total,
                        "ratio": round(ratio, 2),
                    },
                })

        # ── 2. Log type spikes ───────────────────────────────────────────────
        for log_type, current_count in dataset.log_type_counts.items():
            avg_count = self._baseline.avg_log_type_counts.get(log_type, 0)
            if avg_count > 0:
                type_ratio = current_count / avg_count
                if type_ratio >= self.VOLUME_SPIKE_THRESHOLD:
                    anomalies.append({
                        "type": "log_type_spike",
                        "severity": "high" if type_ratio >= 3.0 else "medium",
                        "description": (
                            f"Log type '{log_type}' volume is {type_ratio:.1f}x baseline "
                            f"({current_count:,} vs avg {avg_count:,.0f})"
                        ),
                        "details": {
                            "log_type": log_type,
                            "current": current_count,
                            "average": avg_count,
                            "ratio": round(type_ratio, 2),
                        },
                    })
            elif current_count > 100:
                # New log type with significant volume
                anomalies.append({
                    "type": "new_log_type",
                    "severity": "medium",
                    "description": (
                        f"New log type '{log_type}' appeared with {current_count:,} events "
                        f"(no historical baseline)"
                    ),
                    "details": {"log_type": log_type, "current": current_count},
                })

        # ── 3. High-volume source IPs not in recent baseline ─────────────────
        historical_ips = set()
        for h in self._baseline.history:
            # We don't store full IP lists in baseline, so skip if not available
            pass

        # ── 4. Action distribution anomalies ─────────────────────────────────
        for action, current_count in dataset.action_counts.items():
            avg_count = self._baseline.avg_action_counts.get(action, 0)
            if avg_count > 0:
                action_ratio = current_count / avg_count
                if action_ratio >= 3.0 and current_count > 500:
                    anomalies.append({
                        "type": "action_spike",
                        "severity": "high",
                        "description": (
                            f"Action '{action}' volume is {action_ratio:.1f}x baseline "
                            f"({current_count:,} vs avg {avg_count:,.0f})"
                        ),
                        "details": {
                            "action": action,
                            "current": current_count,
                            "average": avg_count,
                            "ratio": round(action_ratio, 2),
                        },
                    })

        # ── 5. Port-based anomalies (sensitive ports) ────────────────────────
        sensitive_ports = {22, 2222, 3306, 5432, 6379, 9200, 10022, 3389, 445, 135}
        for entry in dataset.top_destination_ports:
            try:
                port = int(entry.key)
            except (ValueError, TypeError):
                continue
            if port in sensitive_ports and entry.count > 100:
                anomalies.append({
                    "type": "sensitive_port_activity",
                    "severity": "high" if entry.count > 1000 else "medium",
                    "description": (
                        f"High volume on sensitive port {port}: {entry.count:,} events"
                    ),
                    "details": {
                        "port": port,
                        "count": entry.count,
                    },
                })

        logger.info("Anomaly detection complete: %d anomalies found", len(anomalies))
        return anomalies


__all__ = ["BaselineTracker"]
