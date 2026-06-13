"""
Investigation Queue Writer — bridges AI Alert to Threat Hunter.

When AI Alert emits an alert, it writes a compact investigation request
to a shared JSONL file. The Threat Hunter watches this file and triggers
an immediate investigation instead of waiting for the 6-hour schedule.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger(__name__)


def write_investigation_request(
    queue_path: Path,
    alert_data: Dict[str, Any],
) -> None:
    """
    Append an investigation request derived from an AI Alert to the shared queue.

    The request contains enough context for the Threat Hunter to build a
    hypothesis and start an MCP-based investigation immediately.
    """
    analysis = alert_data.get("analysis", {})
    event = alert_data.get("event", {})

    # Extract key fields the Threat Hunter needs
    request = {
        "type": "alert_investigation",
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": "ai_alert",
        "processed": False,

        # Alert identification
        "alert_severity": analysis.get("severity", "medium"),
        "alert_confidence": analysis.get("confidence", 50),
        "alert_category": analysis.get("category", "unknown"),
        "alert_title": analysis.get("title", ""),
        "alert_summary": analysis.get("summary", ""),
        "alert_reasoning": analysis.get("reasoning", ""),
        "dedup_key": analysis.get("dedup_key", ""),
        "recommended_actions": analysis.get("recommended_actions", []),

        # Event context for building hypotheses
        "window_summary": {
            "window": event.get("window", {}),
            "dominant_log_type": event.get("dominant_log_type", ""),
            "dominant_action": event.get("dominant_action", ""),
            "log_type_counts": event.get("log_type_counts", {}),
            "action_counts": event.get("action_counts", {}),
            "top_source_ips": event.get("top_source_ips", []),
            "top_destination_ips": event.get("top_destination_ips", []),
            "top_groups": event.get("top_groups", []),
            "notable_patterns": event.get("notable_patterns", {}),
        },
    }

    try:
        queue_path.parent.mkdir(parents=True, exist_ok=True)
        with queue_path.open("a", encoding="utf-8") as fh:
            fh.write(
                json.dumps(request, separators=(",", ":"), ensure_ascii=False)
            )
            fh.write("\n")
        logger.info(
            "Investigation request queued: [%s] %s",
            request["alert_severity"].upper(),
            request["alert_title"][:80],
        )
    except Exception:
        logger.exception("Failed to write investigation request to %s", queue_path)


__all__ = ["write_investigation_request"]
