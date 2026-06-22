from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import httpx  # type: ignore[import-not-found]

from ..config import AppConfig
from ..models import Alert

logger = logging.getLogger(__name__)


def _format_cost(cost: float | int | None) -> str:
    return f"${float(cost or 0.0):.8f}"


def _format_correlation_line(event: Dict[str, Any]) -> str | None:
    correlation = event.get("historical_correlation")
    if not isinstance(correlation, dict):
        return None

    matching_windows = correlation.get("matching_windows_last_hour")
    continuous_minutes = correlation.get("continuous_minutes")
    lookback_seconds = correlation.get("lookback_seconds")

    if matching_windows is None or continuous_minutes is None:
        return None

    try:
        lookback_hours = max(1, int(int(lookback_seconds or 3600) // 3600))
    except (TypeError, ValueError):
        lookback_hours = 1

    return (
        "Correlation: "
        f"{matching_windows} matching windows / "
        f"{continuous_minutes} continuous minutes / "
        f"{lookback_hours}h"
    )


def format_telegram_message(alert: Alert) -> str:
    analysis = alert.analysis
    event = alert.event
    window = event.get("window")
    period = event.get("period")
    usage = alert.usage or {}
    request_usage = usage.get("request") if isinstance(usage, dict) else {}
    daily_usage = usage.get("daily") if isinstance(usage, dict) else {}

    lines = [
        f"ALERT {analysis.severity.upper()} {analysis.confidence}%",
        analysis.title,
        f"Category: {analysis.category}",
    ]

    if isinstance(window, dict):
        start = window.get("start") or "-"
        end = window.get("end") or "-"
        total = window.get("aggregated_record_count") or window.get("event_count") or "-"
        dominant_log_type = event.get("dominant_log_type") or "-"
        flush_reason = window.get("flush_reason") or "-"
        lines.append(
            f"Window: {start} -> {end} | total={total} | type={dominant_log_type} | reason={flush_reason}"
        )
    elif isinstance(period, dict):
        start = period.get("start") or "-"
        end = period.get("end") or "-"
        batches = event.get("batches_analyzed") or "-"
        events = event.get("event_count") or "-"
        lines.append(f"Period: {start} -> {end} | batches={batches} | events={events}")
    else:
        src_ip = event.get("src_ip") or "-"
        dst_ip = event.get("dst_ip") or "-"
        log_type = event.get("log_type") or "-"
        lines.append(f"Event: src={src_ip} dst={dst_ip} type={log_type}")

    if isinstance(request_usage, dict):
        lines.append(
            "LLM usage: "
            f"prompt={request_usage.get('prompt_tokens', 0)} "
            f"cached={request_usage.get('cached_tokens', 0)} "
            f"completion={request_usage.get('completion_tokens', 0)} "
            f"cost={_format_cost(request_usage.get('total_cost_usd'))} "
            f"today={_format_cost((daily_usage or {}).get('total_cost_usd'))}"
        )

    correlation_line = _format_correlation_line(event)
    if correlation_line:
        lines.append(correlation_line)

    if analysis.summary:
        lines.append(f"Summary: {analysis.summary}")

    if analysis.recommended_actions:
        lines.append("Actions:")
        for action in analysis.recommended_actions[:4]:
            lines.append(f"- {action}")

    lines.append(f"Dedup: {analysis.dedup_key or '-'}")
    return "\n".join(lines)


def format_no_alert_status_message(summary: Dict[str, Any]) -> str:
    period = summary.get("period") or {}
    batches = summary.get("batches_analyzed", 0)
    events = summary.get("event_count", 0)
    total = summary.get("aggregated_record_count", 0)
    llm_usage = summary.get("llm_usage") or {}
    daily_usage = summary.get("daily_llm_usage") or {}
    analysis = summary.get("analysis") or {}

    lines = [
        "STATUS No important alerts in interval",
        "System state: normal.",
        "No important security alerts were generated during this reporting interval.",
        f"Period: {period.get('start', '-')} -> {period.get('end', '-')}",
        f"Processed: batches={batches} | events={events} | aggregated_records={total}",
    ]

    if analysis:
        title = analysis.get("title")
        summary_text = analysis.get("summary")
        if title:
            lines.append(f"Assessment: {title}")
        if summary_text:
            lines.append(f"AI summary: {summary_text}")

    if llm_usage:
        lines.append(
            "LLM cost: "
            f"interval={_format_cost(llm_usage.get('total_cost_usd'))} "
            f"today={_format_cost(daily_usage.get('total_cost_usd'))}"
        )
        lines.append(
            "LLM tokens: "
            f"calls={llm_usage.get('calls', 0)} "
            f"prompt={llm_usage.get('prompt_tokens', 0)} "
            f"cached={llm_usage.get('cached_tokens', 0)} "
            f"completion={llm_usage.get('completion_tokens', 0)}"
        )

    log_type_counts = summary.get("log_type_counts") or {}
    if log_type_counts:
        lines.append(
            "Log types: "
            + ", ".join(f"{key}={value}" for key, value in list(log_type_counts.items())[:5])
        )

    action_counts = summary.get("action_counts") or {}
    if action_counts:
        lines.append(
            "Actions: "
            + ", ".join(f"{key}={value}" for key, value in list(action_counts.items())[:5])
        )

    top_source_ips = summary.get("top_source_ips") or []
    if top_source_ips:
        lines.append(
            "Top sources: "
            + ", ".join(
                f"{row.get('ip')}={row.get('count')}" for row in top_source_ips[:3]
            )
        )

    top_destination_ips = summary.get("top_destination_ips") or []
    if top_destination_ips:
        lines.append(
            "Top destinations: "
            + ", ".join(
                f"{row.get('ip')}={row.get('count')}" for row in top_destination_ips[:3]
            )
        )

    if summary.get("batches_analyzed", 0) == 0:
        lines.append("No batches were processed in this interval.")
    else:
        lines.append(
            "Observed activity remained within current suppression and triage thresholds."
        )

    return "\n".join(lines)


class TelegramNotifier:
    def __init__(self, config: AppConfig) -> None:
        self._bot_token = config.telegram_bot_token
        self._chat_id = config.telegram_chat_id
        self._enabled = bool(self._bot_token and self._chat_id)
        self._client: Optional[httpx.Client] = None

        if self._enabled:
            self._client = httpx.Client(
                base_url=f"https://api.telegram.org/bot{self._bot_token}",
                timeout=config.telegram_timeout_seconds,
            )

    @property
    def enabled(self) -> bool:
        return self._enabled

    def send_alert(self, alert: Alert) -> None:
        if not self._enabled or self._client is None:
            return

        self._send_text(format_telegram_message(alert), error_prefix="Failed to send Telegram alert.")

    def send_status_summary(self, summary: Dict[str, Any]) -> None:
        if not self._enabled or self._client is None:
            return

        self._send_text(
            format_no_alert_status_message(summary),
            error_prefix="Failed to send Telegram no-alert status.",
        )

    def _send_text(self, text: str, error_prefix: str) -> None:
        if not self._enabled or self._client is None:
            return

        payload = {
            "chat_id": self._chat_id,
            "text": text,
            "disable_web_page_preview": True,
        }

        try:
            response = self._client.post("/sendMessage", json=payload)
            response.raise_for_status()
            data = response.json()
            if not data.get("ok", False):
                logger.error("Telegram sendMessage failed: %s", data)
        except Exception:
            logger.exception(error_prefix)

    def close(self) -> None:
        if self._client is not None:
            self._client.close()


__all__ = [
    "TelegramNotifier",
    "format_no_alert_status_message",
    "format_telegram_message",
]
