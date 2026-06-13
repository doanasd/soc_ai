from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from .config import HuntConfig
from .mcp_client import MCPClient
from .models import HuntDataset, TopEntry, HourlyVolume

logger = logging.getLogger(__name__)


class DataCollector:
    """
    Collects overview / aggregation data from OpenSearch via the MCP client.
    Produces a lightweight HuntDataset containing:
    - Total log counts by type (waf, vpc, linux, win)
    - Action distribution (block, allow, ...)
    - Top 50 source IPs, destination IPs, destination ports
    - Hourly volume distribution
    """

    def __init__(self, config: HuntConfig, mcp_client: MCPClient) -> None:
        self._config = config
        self._mcp = mcp_client

    def collect(self, lookback_hours: Optional[int] = None) -> HuntDataset:
        """
        Run aggregation queries against OpenSearch and assemble a HuntDataset.
        """
        hours = lookback_hours or self._config.hunt_lookback_hours
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=hours)

        time_range = {
            "gte": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "lte": now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        }

        logger.info(
            "DataCollector: Collecting overview for last %dh (%s → %s)",
            hours, time_range["gte"], time_range["lte"],
        )

        dataset = HuntDataset(
            lookback_hours=hours,
            time_range_start=time_range["gte"],
            time_range_end=time_range["lte"],
        )

        # ── 1. Totals by log_type and action ─────────────────────────────────
        try:
            counts = self._query_type_and_action_counts(time_range)
            dataset.total_logs = counts.get("total", 0)
            dataset.log_type_counts = counts.get("log_types", {})
            dataset.action_counts = counts.get("actions", {})
        except Exception:
            logger.exception("Failed to collect log type/action counts")

        # ── 2. Top source IPs ────────────────────────────────────────────────
        try:
            dataset.top_source_ips = self._query_top_field(
                "network.source_ip", time_range, size=50
            )
            dataset.unique_source_ips = len(dataset.top_source_ips)
        except Exception:
            logger.exception("Failed to collect top source IPs")

        # ── 3. Top destination IPs ───────────────────────────────────────────
        try:
            dataset.top_destination_ips = self._query_top_field(
                "network.destination_ip", time_range, size=50
            )
            dataset.unique_destination_ips = len(dataset.top_destination_ips)
        except Exception:
            logger.exception("Failed to collect top destination IPs")

        # ── 4. Top destination ports ─────────────────────────────────────────
        try:
            dataset.top_destination_ports = self._query_top_field(
                "network.destination_port", time_range, size=30
            )
        except Exception:
            logger.exception("Failed to collect top destination ports")

        # ── 5. Hourly volume ─────────────────────────────────────────────────
        try:
            dataset.hourly_volume = self._query_hourly_volume(time_range)
        except Exception:
            logger.exception("Failed to collect hourly volume")

        logger.info(
            "DataCollector: Overview complete — total=%d, types=%s, unique_src=%d",
            dataset.total_logs,
            dataset.log_type_counts,
            dataset.unique_source_ips,
        )
        return dataset

    def _query_type_and_action_counts(
        self, time_range: Dict[str, str]
    ) -> Dict[str, Any]:
        """Get total count, breakdown by log_type, and breakdown by action."""
        agg_body = {
            "log_types": {
                "terms": {"field": "log_type.keyword", "size": 20}
            },
            "actions": {
                "terms": {"field": "action.keyword", "size": 20}
            },
        }

        result = self._mcp.get_aggregations(agg_body, query="*", time_range=time_range)
        aggs = result.get("aggregations", {})

        # Parse log_type buckets
        log_types = {}
        for bucket in self._extract_buckets(aggs, "log_types"):
            log_types[bucket.get("key", "unknown")] = bucket.get("doc_count", 0)

        # Parse action buckets
        actions = {}
        for bucket in self._extract_buckets(aggs, "actions"):
            actions[bucket.get("key", "unknown")] = bucket.get("doc_count", 0)

        total = sum(log_types.values()) if log_types else 0

        return {"total": total, "log_types": log_types, "actions": actions}

    def _query_top_field(
        self,
        field: str,
        time_range: Dict[str, str],
        size: int = 50,
    ) -> List[TopEntry]:
        """Get top-N values for a given field."""
        agg_body = {
            "top_values": {
                "terms": {"field": f"{field}.keyword", "size": size}
            }
        }

        # Try with .keyword first, fall back to raw field
        result = self._mcp.get_aggregations(agg_body, query="*", time_range=time_range)
        aggs = result.get("aggregations", {})
        buckets = self._extract_buckets(aggs, "top_values")

        if not buckets:
            # Retry without .keyword suffix
            agg_body = {
                "top_values": {
                    "terms": {"field": field, "size": size}
                }
            }
            result = self._mcp.get_aggregations(agg_body, query="*", time_range=time_range)
            aggs = result.get("aggregations", {})
            buckets = self._extract_buckets(aggs, "top_values")

        entries = []
        for bucket in buckets:
            key = str(bucket.get("key", ""))
            count = int(bucket.get("doc_count", 0))
            if key:
                entries.append(TopEntry(key=key, count=count))

        return entries

    def _query_hourly_volume(
        self, time_range: Dict[str, str]
    ) -> List[HourlyVolume]:
        """Get log volume bucketed by hour."""
        agg_body = {
            "hourly": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": "1h",
                    "format": "yyyy-MM-dd'T'HH:mm:ss",
                }
            }
        }

        result = self._mcp.get_aggregations(agg_body, query="*", time_range=time_range)
        aggs = result.get("aggregations", {})
        buckets = self._extract_buckets(aggs, "hourly")

        volumes = []
        for bucket in buckets:
            key_str = bucket.get("key_as_string", "")
            count = int(bucket.get("doc_count", 0))
            if key_str:
                volumes.append(HourlyVolume(hour=key_str, count=count))

        return volumes

    @staticmethod
    def _extract_buckets(aggs: Dict[str, Any], agg_name: str) -> List[Dict[str, Any]]:
        """Safely extract buckets from aggregation result."""
        agg = aggs.get(agg_name, {})
        if isinstance(agg, dict):
            buckets = agg.get("buckets", [])
            return buckets if isinstance(buckets, list) else []
        return []


__all__ = ["DataCollector"]
