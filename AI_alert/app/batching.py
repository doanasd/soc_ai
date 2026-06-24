from __future__ import annotations

import ipaddress
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .models import Event

SENSITIVE_DESTINATION_PORTS = {
    22,
    2222,
    3306,
    5432,
    6379,
    9200,
    10022,
}


def event_time_utc(event: Event) -> datetime:
    if event.timestamp is None:
        return datetime.now(timezone.utc)
    if event.timestamp.tzinfo is None:
        return event.timestamp.replace(tzinfo=timezone.utc)
    return event.timestamp.astimezone(timezone.utc)


def _window_start(ts: datetime, window_seconds: int) -> datetime:
    epoch = int(ts.timestamp())
    start_epoch = epoch - (epoch % window_seconds)
    return datetime.fromtimestamp(start_epoch, tz=timezone.utc)


@dataclass(frozen=True)
class WindowBatch:
    events: List[Event]
    window_start: datetime
    window_end: datetime
    first_observed_at: datetime
    last_observed_at: datetime
    flush_reason: str


def window_batch_to_dict(batch: WindowBatch) -> Dict[str, Any]:
    return {
        "events": [event.model_dump(mode="json") for event in batch.events],
        "window_start": batch.window_start.isoformat().replace("+00:00", "Z"),
        "window_end": batch.window_end.isoformat().replace("+00:00", "Z"),
        "first_observed_at": batch.first_observed_at.isoformat().replace("+00:00", "Z"),
        "last_observed_at": batch.last_observed_at.isoformat().replace("+00:00", "Z"),
        "flush_reason": batch.flush_reason,
    }


def window_batch_from_dict(data: Dict[str, Any]) -> WindowBatch:
    return WindowBatch(
        events=[Event.model_validate(item) for item in data.get("events", [])],
        window_start=datetime.fromisoformat(str(data["window_start"]).replace("Z", "+00:00")),
        window_end=datetime.fromisoformat(str(data["window_end"]).replace("Z", "+00:00")),
        first_observed_at=datetime.fromisoformat(
            str(data["first_observed_at"]).replace("Z", "+00:00")
        ),
        last_observed_at=datetime.fromisoformat(
            str(data["last_observed_at"]).replace("Z", "+00:00")
        ),
        flush_reason=str(data.get("flush_reason") or "retry"),
    )


class EventBatcher:
    """Group ordered events into fixed time windows."""

    def __init__(self, window_seconds: int) -> None:
        self._window_seconds = window_seconds
        self._current_window_start: Optional[datetime] = None
        self._current_window_end: Optional[datetime] = None
        self._last_activity_at: Optional[datetime] = None
        self._first_observed_at: Optional[datetime] = None
        self._events: List[Event] = []

    def add(
        self, event: Event, observed_at: Optional[datetime] = None
    ) -> Optional[WindowBatch]:
        activity_time = observed_at or datetime.now(timezone.utc)
        window_start = _window_start(activity_time, self._window_seconds)

        if self._current_window_start is None:
            self._current_window_start = window_start
            self._current_window_end = window_start + timedelta(seconds=self._window_seconds)
            self._first_observed_at = activity_time
            self._last_activity_at = activity_time
            self._events.append(event)
            return None

        if window_start == self._current_window_start:
            self._last_activity_at = activity_time
            self._events.append(event)
            return None

        ready = self.flush(flush_reason="window_rollover")
        self._current_window_start = window_start
        self._current_window_end = window_start + timedelta(seconds=self._window_seconds)
        self._first_observed_at = activity_time
        self._last_activity_at = activity_time
        self._events = [event]
        return ready

    def has_pending(self) -> bool:
        return bool(self._events)

    def should_flush(
        self,
        now: Optional[datetime] = None,
        idle_timeout_seconds: Optional[int] = None,
    ) -> bool:
        if not self._events:
            return False

        current_time = now or datetime.now(timezone.utc)
        if self._current_window_end is not None and current_time >= self._current_window_end:
            return True

        if (
            idle_timeout_seconds is not None
            and idle_timeout_seconds > 0
            and self._last_activity_at is not None
        ):
            idle_deadline = self._last_activity_at + timedelta(seconds=idle_timeout_seconds)
            if current_time >= idle_deadline:
                return True

        return False

    def flush(self, flush_reason: str = "manual") -> Optional[WindowBatch]:
        if (
            not self._events
            or self._current_window_start is None
            or self._current_window_end is None
            or self._first_observed_at is None
            or self._last_activity_at is None
        ):
            return None

        ready = WindowBatch(
            events=self._events,
            window_start=self._current_window_start,
            window_end=self._current_window_end,
            first_observed_at=self._first_observed_at,
            last_observed_at=self._last_activity_at,
            flush_reason=flush_reason,
        )
        self._events = []
        self._current_window_start = None
        self._current_window_end = None
        self._first_observed_at = None
        self._last_activity_at = None
        return ready


def build_window_summary(batch: WindowBatch, configured_window_seconds: int) -> Dict[str, Any]:
    if not batch.events:
        raise ValueError("events must not be empty")

    event_dicts = [event.model_dump(mode="json") for event in batch.events]
    event_timestamps = sorted(
        event_time_utc(event) for event in batch.events if event.timestamp is not None
    )

    log_type_counts: Counter[str] = Counter()
    action_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    destination_counts: Counter[str] = Counter()
    weighted_total = 0

    grouped_rows: List[Dict[str, Any]] = []
    external_sensitive_rows: List[Dict[str, Any]] = []

    for data in event_dicts:
        aggregation = data.get("aggregation") or {}
        sample_event = data.get("sample_event") or {}
        network = sample_event.get("network") or {}

        weight_raw = aggregation.get("count", 1)
        try:
            weight = max(1, int(weight_raw))
        except (TypeError, ValueError):
            weight = 1

        weighted_total += weight

        log_type = str(data.get("log_type") or "unknown")
        action = str(data.get("action") or sample_event.get("action") or "unknown")
        src_ip = data.get("src_ip") or network.get("source_ip")
        dst_ip = data.get("dst_ip") or network.get("destination_ip")
        dst_port = network.get("destination_port")
        protocol = network.get("protocol")

        log_type_counts[log_type] += weight
        action_counts[action] += weight

        if src_ip:
            source_counts[str(src_ip)] += weight
        if dst_ip:
            destination_counts[str(dst_ip)] += weight

        # Extract enrichment data từ enrichments dict (enricher v2) + backward-compat maliciousIP
        enrichments = sample_event.get("enrichments") or {}
        mal_ip      = sample_event.get("maliciousIP")
        mal_info    = None

        # Ưu tiên enrichments dict mới (đầy đủ hơn)
        # Tìm IP nguồn trong enrichments trước
        _src_candidate = data.get("src_ip") or network.get("source_ip") or ""
        _enrich_rec = enrichments.get(_src_candidate) if _src_candidate else None

        # Nếu không tìm được theo src_ip, lấy bất kỳ record nào is_malicious=True
        if not _enrich_rec:
            for _ip_key, _rec in enrichments.items():
                if isinstance(_rec, dict) and _rec.get("confidence_score", 0) > 0:
                    _enrich_rec = _rec
                    break

        if isinstance(_enrich_rec, dict) and _enrich_rec.get("confidence_score", 0) >= 0:
            otx = _enrich_rec.get("otx_context") or {}
            tf  = _enrich_rec.get("threat_feed_context") or {}
            mal_info = {
                "confidence_score":  _enrich_rec.get("confidence_score", 0),
                "is_malicious":      bool(_enrich_rec.get("is_malicious")),
                "threat_severity":   _enrich_rec.get("threat_severity", "none"),
                "reputation":        _enrich_rec.get("reputation", "benign"),
                "isp":               _enrich_rec.get("isp", ""),
                "asn":               _enrich_rec.get("asn", ""),
                "country_code":      _enrich_rec.get("country", ""),
                "country_name":      _enrich_rec.get("country_name", ""),
                "city":              _enrich_rec.get("city", ""),
                "usage_type":        _enrich_rec.get("usage_type", ""),
                "hostname":          _enrich_rec.get("hostname", ""),
                "domain":            _enrich_rec.get("domain", ""),
                "categories":        [_enrich_rec.get("category", "")] if _enrich_rec.get("category","") not in ("","clean") else [],
                "is_tor":            bool(_enrich_rec.get("is_tor")),
                "is_whitelisted":    bool(_enrich_rec.get("is_whitelisted")),
                "total_reports":     _enrich_rec.get("total_reports", 0),
                "source":            "abuseipdb",
                # OTX context
                "otx_pulse_count":   otx.get("pulse_count", 0),
                "otx_tags":          otx.get("tags", [])[:5],
                "otx_malware":       otx.get("malware_families", [])[:3],
                # ThreatFeed context
                "urlhaus_count":     tf.get("urlhaus_url_count", 0),
                "urlhaus_tags":      tf.get("urlhaus_tags", [])[:3],
                "threatfox_malware": tf.get("threatfox_malware", [])[:3],
            }
        elif isinstance(mal_ip, dict) and mal_ip.get("confidence_score", 0) > 0:
            # Fallback backward-compat
            mal_info = {
                "confidence_score": mal_ip.get("confidence_score"),
                "is_malicious":     True,
                "threat_severity":  "high" if mal_ip.get("confidence_score",0) >= 75 else "medium",
                "reputation":       "malicious",
                "isp":              mal_ip.get("isp", ""),
                "asn":              "",
                "country_code":     mal_ip.get("country_code", ""),
                "country_name":     "",
                "city":             "",
                "usage_type":       "",
                "hostname":         "",
                "domain":           "",
                "categories":       mal_ip.get("categories", []),
                "is_tor":           bool(mal_ip.get("is_tor")),
                "is_whitelisted":   False,
                "total_reports":    mal_ip.get("total_reports", 0),
                "source":           mal_ip.get("source", "abuseipdb"),
                "otx_pulse_count":  0,
                "otx_tags":         [],
                "otx_malware":      [],
                "urlhaus_count":    0,
                "urlhaus_tags":     [],
                "threatfox_malware": [],
            }

        row = {
            "group_key": data.get("group_key")
            or f"{log_type}|{src_ip or '-'}|{dst_ip or '-'}|{dst_port or '-'}|{action}",
            "log_type": log_type,
            "action": action,
            "method": data.get("method"),
            "uri": data.get("uri"),
            "rule_id": data.get("rule_id"),
            "reason": data.get("reason"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "destination_port": dst_port,
            "protocol": protocol,
            "count": weight,
            "sample_message": sample_event.get("message") or data.get("message"),
            "malicious_src": mal_info,
        }
        grouped_rows.append(row)

        if _is_public_ip(src_ip) and _is_private_ip(dst_ip) and _is_sensitive_port(dst_port):
            external_sensitive_rows.append(row)

    # Sort: malicious IP lên đầu, sau đó theo count
    def sort_key(item):
        mal = item.get("malicious_src") or {}
        is_mal = 1 if mal.get("is_malicious") else 0
        score = mal.get("confidence_score", 0) or 0
        return (is_mal, score, item["count"])
    grouped_rows.sort(key=sort_key, reverse=True)
    external_sensitive_rows.sort(key=lambda item: item["count"], reverse=True)

    dominant_log_type = log_type_counts.most_common(1)[0][0]
    dominant_action = action_counts.most_common(1)[0][0]

    return {
        "window": {
            "start": batch.window_start.isoformat().replace("+00:00", "Z"),
            "end": batch.window_end.isoformat().replace("+00:00", "Z"),
            "configured_window_seconds": configured_window_seconds,
            "observed_span_seconds": max(
                1, int((batch.last_observed_at - batch.first_observed_at).total_seconds()) + 1
            ),
            "event_count": len(batch.events),
            "aggregated_record_count": weighted_total,
            "flush_reason": batch.flush_reason,
            "first_observed_at": batch.first_observed_at.isoformat().replace("+00:00", "Z"),
            "last_observed_at": batch.last_observed_at.isoformat().replace("+00:00", "Z"),
        },
        "event_time_range": {
            "start": event_timestamps[0].isoformat().replace("+00:00", "Z")
            if event_timestamps
            else None,
            "end": event_timestamps[-1].isoformat().replace("+00:00", "Z")
            if event_timestamps
            else None,
        },
        "dominant_log_type": dominant_log_type,
        "dominant_action": dominant_action,
        "log_type_counts": dict(log_type_counts.most_common()),
        "action_counts": dict(action_counts.most_common()),
        "top_source_ips": [
            {"ip": ip, "count": count} for ip, count in source_counts.most_common(10)
        ],
        "top_destination_ips": [
            {"ip": ip, "count": count}
            for ip, count in destination_counts.most_common(10)
        ],
        "top_groups": grouped_rows[:25],
        "notable_patterns": {
            "external_to_private_sensitive": external_sensitive_rows[:10],
        },
    }


def representative_event_for_batch(batch: WindowBatch) -> Event:
    summary = build_window_summary(batch, configured_window_seconds=1)
    dominant_log_type = summary["dominant_log_type"]
    dominant_action = summary["dominant_action"]

    for event in batch.events:
        if event.log_type == dominant_log_type and (event.action or "unknown") == dominant_action:
            return event
    for event in batch.events:
        if event.log_type == dominant_log_type:
            return event
    return batch.events[0]


def _is_sensitive_port(value: Any) -> bool:
    try:
        return int(value) in SENSITIVE_DESTINATION_PORTS
    except (TypeError, ValueError):
        return False


def _is_public_ip(value: Any) -> bool:
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
    )


def _is_private_ip(value: Any) -> bool:
    try:
        return ipaddress.ip_address(str(value)).is_private
    except ValueError:
        return False


__all__ = [
    "EventBatcher",
    "WindowBatch",
    "build_window_summary",
    "event_time_utc",
    "representative_event_for_batch",
    "window_batch_from_dict",
    "window_batch_to_dict",
]
