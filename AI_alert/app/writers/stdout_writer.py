from __future__ import annotations

from . import jsonl_writer  # pragma: no cover
from ..models import Alert


def _format_cost(cost: float | int | None) -> str:
    return f"${float(cost or 0.0):.8f}"


def format_summary(alert: Alert) -> str:
    """Return a compact single-line summary for stdout."""

    a = alert.analysis
    event = alert.event
    usage = alert.usage or {}
    request_usage = usage.get("request") if isinstance(usage, dict) else {}
    daily_usage = usage.get("daily") if isinstance(usage, dict) else {}
    cost_suffix = ""
    if isinstance(request_usage, dict):
        cost_suffix = (
            f" cost={_format_cost(request_usage.get('total_cost_usd'))}"
            f" today={_format_cost((daily_usage or {}).get('total_cost_usd'))}"
        )
    window = event.get("window")
    if isinstance(window, dict):
        start = window.get("start") or "-"
        end = window.get("end") or "-"
        total = window.get("aggregated_record_count") or window.get("event_count") or "-"
        log_type = event.get("dominant_log_type") or "-"
        return (
            f"[{a.severity.upper()}][{a.confidence}%][{a.category}] "
            f"{a.title} window={start}->{end} total={total} type={log_type}{cost_suffix}"
        )

    src_ip = event.get("src_ip") or "-"
    dst_ip = event.get("dst_ip") or "-"
    log_type = event.get("log_type") or "-"

    return (
        f"[{a.severity.upper()}][{a.confidence}%][{a.category}] "
        f"{a.title} src={src_ip} dst={dst_ip} type={log_type}{cost_suffix}"
    )


def print_summary(alert: Alert) -> None:
    """Print human-readable alert summary to stdout."""

    print(format_summary(alert))


__all__ = ["format_summary", "print_summary"]
