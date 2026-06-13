from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import pytest  # type: ignore[import-not-found]

from app.batching import EventBatcher, WindowBatch, build_window_summary
from app.config import AppConfig
from app.cost_tracker import ModelCallRecord, ModelCostTracker
from app.context_loader import ContextLoader
from app.analyzer import Analyzer
from app.alert_engine import AlertEngine
from app.groq_client import GroqClient
from app.reader import LogFollower
from app.retry_queue import FailedBatchQueue
from app.models import (
    Alert,
    BatchAnalysisResult,
    Event,
    GroqChatResult,
    MODEL_ANALYSIS_JSON_SCHEMA,
    ModelUsage,
    parse_model_analysis,
)
from app.prompt_builder import build_messages, build_status_messages, build_window_messages
from app.status_reporter import NoAlertStatusReporter
from app.writers.telegram_writer import (
    TelegramNotifier,
    format_no_alert_status_message,
    format_telegram_message,
)
from app.window_history import WindowCorrelationTracker


def make_config(tmp_path: Path) -> AppConfig:
    return AppConfig(
        log_input_path=tmp_path / "log_dedup.json",
        alert_output_path=tmp_path / "alerts.jsonl",
        context_dir=tmp_path / "context",
        failed_batch_spool_path=tmp_path / "failed_batches.jsonl",
        log_start_position="end",
        groq_api_key="test",
        groq_model="test-model",
        groq_timeout_seconds=5,
        groq_max_retries=1,
        groq_max_completion_tokens=1024,
        groq_input_cost_per_million=0.15,
        groq_cached_input_cost_per_million=0.075,
        groq_output_cost_per_million=0.60,
        model_usage_report_path=tmp_path / "model_usage_costs.txt",
        telegram_bot_token="",
        telegram_chat_id="",
        telegram_timeout_seconds=10,
        no_alert_summary_interval_seconds=3600,
        retry_failed_batches=True,
        retry_base_delay_seconds=30,
        retry_max_delay_seconds=900,
        retry_max_attempts=8,
        batch_window_seconds=300,
        batch_idle_timeout_seconds=300,
        poll_interval_seconds=0.1,
        alert_suppression_ttl_seconds=60,
        correlation_lookback_seconds=3600,
        max_context_chars=2000,
        log_level=20,
    )


def test_event_parsing_minimal():
    data: Dict[str, Any] = {"log_type": "waf", "src_ip": "1.2.3.4"}
    event = Event.model_validate(data)
    assert event.log_type == "waf"
    assert event.src_ip == "1.2.3.4"


def test_event_parsing_flattens_nested_vpc_fields():
    data: Dict[str, Any] = {
        "sample_event": {
            "time": "1773720190000.000000",
            "log_type": "vpc",
            "vendor": "aws",
            "action": "accept",
            "message": "flow message",
            "network": {
                "source_ip": "45.79.225.32",
                "destination_ip": "10.141.1.64",
                "country": "US",
            },
        }
    }

    event = Event.model_validate(data)
    assert event.log_type == "vpc"
    assert event.source == "aws"
    assert event.action == "accept"
    assert event.src_ip == "45.79.225.32"
    assert event.dst_ip == "10.141.1.64"
    assert event.country == "US"
    assert event.message == "flow message"
    assert event.timestamp is not None


def test_context_loading(tmp_path: Path):
    context_dir = tmp_path / "context"
    context_dir.mkdir()
    (context_dir / "01_environment.md").write_text("env", encoding="utf-8")
    (context_dir / "02_detection_policy.md").write_text("policy", encoding="utf-8")

    loader = ContextLoader(context_dir, max_chars=50)
    event = Event(log_type="waf")
    ctx = loader.build_context(event)
    assert "env" in ctx
    assert "policy" in ctx


def test_context_loader_can_build_full_context(tmp_path: Path):
    context_dir = tmp_path / "context"
    context_dir.mkdir()
    (context_dir / "01_environment.md").write_text("env", encoding="utf-8")
    (context_dir / "02_detection_policy.md").write_text("policy", encoding="utf-8")

    loader = ContextLoader(context_dir, max_chars=200)
    ctx = loader.build_full_context()
    assert "01_environment.md" in ctx
    assert "02_detection_policy.md" in ctx


def test_prompt_build_and_model_parsing_sanitization():
    raw = {
        "should_alert": "true",
        "severity": "CRITICAL",
        "confidence": "150",
        "category": "test",
        "title": "Test alert",
        "summary": "",
        "reasoning": "",
        "recommended_actions": [],
        "dedup_key": "k1",
    }

    analysis = parse_model_analysis(raw)
    assert analysis.should_alert is True
    assert analysis.severity == "critical"
    assert 0 <= analysis.confidence <= 100


def test_prompt_build_serializes_valid_json():
    event = Event(log_type="waf", src_ip="1.2.3.4", labels=["a", "b"])
    messages = build_messages(event, "ctx")

    user_message = messages[1].content
    assert '"src_ip": "1.2.3.4"' in user_message
    assert "'src_ip': '1.2.3.4'" not in user_message


def test_window_prompt_build_serializes_summary_json():
    summary = {
        "window": {"start": "2026-03-17T00:00:00Z", "end": "2026-03-17T00:05:00Z"},
        "dominant_log_type": "vpc",
    }
    messages = build_window_messages(summary, "ctx")

    user_message = messages[1].content
    assert '"dominant_log_type": "vpc"' in user_message


def test_gpt_oss_prompt_uses_single_user_message():
    event = Event(log_type="waf", src_ip="1.2.3.4")
    messages = build_messages(event, "ctx", "openai/gpt-oss-120b")

    assert len(messages) == 1
    assert messages[0].role == "user"
    assert "experienced Security Operations Center" in messages[0].content


def test_gpt_oss_window_prompt_uses_single_user_message():
    summary = {"window": {"start": "2026-03-17T00:00:00Z"}}
    messages = build_window_messages(summary, "ctx", "openai/gpt-oss-120b")

    assert len(messages) == 1
    assert messages[0].role == "user"
    assert "time-window triage" in messages[0].content


def test_gpt_oss_status_prompt_uses_single_user_message():
    summary = {"period": {"start": "2026-03-17T00:00:00Z"}}
    messages = build_status_messages(summary, "ctx", "openai/gpt-oss-120b")

    assert len(messages) == 1
    assert messages[0].role == "user"
    assert "monitoring health and interval triage" in messages[0].content


def test_malformed_model_output_handling():
    # Non-JSON string should raise ValidationError when parsed directly
    with pytest.raises(Exception):
        parse_model_analysis("not-json")


class DummyGroqClient:
    def __init__(self, payload: Dict[str, Any]) -> None:
        self.payload = payload
        self.model_name = "test-model"
        self.last_messages = None

    def chat(self, messages):
        self.last_messages = messages
        return GroqChatResult(
            content=self.payload,
            usage=ModelUsage(
                model=self.model_name,
                attempts=1,
                successful_calls=1,
                prompt_tokens=100,
                completion_tokens=40,
                total_tokens=140,
                input_cost_usd=0.000015,
                output_cost_usd=0.000024,
                total_cost_usd=0.000039,
            ),
            daily_totals={
                "date": "2026-03-17",
                "calls": 1,
                "successful_calls": 1,
                "failed_calls": 0,
                "prompt_tokens": 100,
                "cached_tokens": 0,
                "completion_tokens": 40,
                "total_tokens": 140,
                "input_cost_usd": 0.000015,
                "cached_input_cost_usd": 0.0,
                "output_cost_usd": 0.000024,
                "total_cost_usd": 0.000039,
            },
        )


class FailingGroqClient:
    def __init__(self) -> None:
        self.model_name = "test-model"

    def chat(self, messages):
        return GroqChatResult(
            content=None,
            usage=ModelUsage(model=self.model_name, attempts=1, failed_calls=1),
            daily_totals={},
        )


def test_event_batcher_flushes_on_window_change():
    batcher = EventBatcher(window_seconds=300)
    e1 = Event(timestamp=datetime(2026, 3, 17, 0, 1, tzinfo=timezone.utc), log_type="vpc")
    e2 = Event(timestamp=datetime(2026, 3, 17, 0, 3, tzinfo=timezone.utc), log_type="vpc")
    e3 = Event(timestamp=datetime(2026, 3, 17, 0, 6, tzinfo=timezone.utc), log_type="vpc")

    assert batcher.add(e1, observed_at=datetime(2026, 3, 17, 13, 0, tzinfo=timezone.utc)) is None
    assert batcher.add(e2, observed_at=datetime(2026, 3, 17, 13, 3, tzinfo=timezone.utc)) is None
    ready = batcher.add(e3, observed_at=datetime(2026, 3, 17, 13, 6, tzinfo=timezone.utc))

    assert ready is not None
    assert len(ready.events) == 2
    assert ready.flush_reason == "window_rollover"
    flushed = batcher.flush()
    assert flushed is not None
    assert flushed.events == [e3]


def test_event_batcher_uses_arrival_time_not_event_timestamp():
    batcher = EventBatcher(window_seconds=300)
    e1 = Event(timestamp=datetime(2026, 3, 17, 0, 1, tzinfo=timezone.utc), log_type="vpc")
    e2 = Event(timestamp=datetime(2026, 3, 17, 4, 59, tzinfo=timezone.utc), log_type="vpc")

    assert batcher.add(e1, observed_at=datetime(2026, 3, 17, 13, 0, 1, tzinfo=timezone.utc)) is None
    ready = batcher.add(e2, observed_at=datetime(2026, 3, 17, 13, 0, 2, tzinfo=timezone.utc))

    assert ready is None


def test_event_batcher_flushes_on_wall_clock_timeout():
    batcher = EventBatcher(window_seconds=300)
    event = Event(timestamp=datetime(2026, 3, 17, 0, 1, tzinfo=timezone.utc), log_type="vpc")

    batcher.add(event, observed_at=datetime(2026, 3, 17, 13, 1, tzinfo=timezone.utc))

    assert (
        batcher.should_flush(
            now=datetime(2026, 3, 17, 13, 4, 59, tzinfo=timezone.utc),
            idle_timeout_seconds=300,
        )
        is False
    )
    assert (
        batcher.should_flush(
            now=datetime(2026, 3, 17, 13, 5, tzinfo=timezone.utc),
            idle_timeout_seconds=300,
        )
        is True
    )


def test_event_batcher_flushes_on_idle_timeout():
    batcher = EventBatcher(window_seconds=300)
    event = Event(timestamp=datetime(2026, 3, 17, 0, 1, tzinfo=timezone.utc), log_type="vpc")

    batcher.add(event, observed_at=datetime(2026, 3, 17, 13, 1, tzinfo=timezone.utc))

    assert (
        batcher.should_flush(
            now=datetime(2026, 3, 17, 13, 1, 29, tzinfo=timezone.utc),
            idle_timeout_seconds=30,
        )
        is False
    )
    assert (
        batcher.should_flush(
            now=datetime(2026, 3, 17, 13, 1, 30, tzinfo=timezone.utc),
            idle_timeout_seconds=30,
        )
        is True
    )


def test_window_summary_counts_aggregated_records():
    events: List[Event] = [
        Event.model_validate(
            {
                "timestamp": "2026-03-17T00:00:00Z",
                "log_type": "vpc",
                "action": "accept",
                "src_ip": "61.242.178.28",
                "dst_ip": "10.141.1.64",
                "aggregation": {"count": 3},
                "sample_event": {
                    "network": {"destination_port": 6379, "protocol": "TCP"},
                    "message": "redis exposure",
                },
            }
        ),
        Event.model_validate(
            {
                "timestamp": "2026-03-17T00:01:00Z",
                "log_type": "vpc",
                "action": "accept",
                "src_ip": "61.242.178.28",
                "dst_ip": "10.141.1.64",
                "aggregation": {"count": 2},
                "sample_event": {
                    "network": {"destination_port": 22, "protocol": "TCP"},
                    "message": "ssh exposure",
                },
            }
        ),
    ]

    batch = WindowBatch(
        events=events,
        window_start=datetime(2026, 3, 17, 13, 0, tzinfo=timezone.utc),
        window_end=datetime(2026, 3, 17, 13, 5, tzinfo=timezone.utc),
        first_observed_at=datetime(2026, 3, 17, 13, 0, 10, tzinfo=timezone.utc),
        last_observed_at=datetime(2026, 3, 17, 13, 4, 59, tzinfo=timezone.utc),
        flush_reason="window_timeout",
    )

    summary = build_window_summary(batch, configured_window_seconds=300)
    assert summary["window"]["aggregated_record_count"] == 5
    assert summary["dominant_log_type"] == "vpc"
    assert summary["action_counts"]["accept"] == 5
    assert len(summary["notable_patterns"]["external_to_private_sensitive"]) == 2
    assert summary["window"]["start"] == "2026-03-17T13:00:00Z"
    assert summary["window"]["end"] == "2026-03-17T13:05:00Z"
    assert summary["event_time_range"]["start"] == "2026-03-17T00:00:00Z"
    assert summary["event_time_range"]["end"] == "2026-03-17T00:01:00Z"


def test_window_summary_keeps_http_fields_for_correlation():
    event = Event.model_validate(
        {
            "timestamp": "2026-03-17T00:00:00Z",
            "log_type": "waf",
            "action": "blocked",
            "src_ip": "27.1.108.122",
            "uri": "/issuing/users",
            "method": "POST",
            "rule_id": "ddos-rate-limit",
            "aggregation": {"count": 10},
        }
    )
    batch = WindowBatch(
        events=[event],
        window_start=datetime(2026, 3, 17, 13, 0, tzinfo=timezone.utc),
        window_end=datetime(2026, 3, 17, 13, 5, tzinfo=timezone.utc),
        first_observed_at=datetime(2026, 3, 17, 13, 0, tzinfo=timezone.utc),
        last_observed_at=datetime(2026, 3, 17, 13, 0, tzinfo=timezone.utc),
        flush_reason="window_timeout",
    )

    summary = build_window_summary(batch, configured_window_seconds=300)

    assert summary["top_groups"][0]["method"] == "POST"
    assert summary["top_groups"][0]["uri"] == "/issuing/users"
    assert summary["top_groups"][0]["rule_id"] == "ddos-rate-limit"


def test_window_correlation_tracker_summarizes_recurrence():
    tracker = WindowCorrelationTracker(lookback_seconds=3600, window_seconds=300)

    def make_summary(start_minute: int) -> Dict[str, Any]:
        window_start = datetime(2026, 3, 17, 13, start_minute, tzinfo=timezone.utc)
        window_end = datetime(2026, 3, 17, 13, start_minute + 5, tzinfo=timezone.utc)
        return {
            "window": {
                "start": window_start.isoformat().replace("+00:00", "Z"),
                "end": window_end.isoformat().replace("+00:00", "Z"),
                "aggregated_record_count": 100,
            },
            "dominant_log_type": "waf",
            "dominant_action": "blocked",
            "top_groups": [
                {
                    "action": "blocked",
                    "method": "POST",
                    "uri": "/issuing/users",
                    "rule_id": "ddos-rate-limit",
                }
            ],
            "top_source_ips": [{"ip": f"27.1.108.{start_minute + 1}", "count": 100}],
        }

    first = tracker.summarize(make_summary(0))
    assert first["matching_windows_last_hour"] == 1
    assert first["severity_signal"] == "isolated_single_window"

    for minute in (0, 5, 10, 15, 20):
        tracker.record(make_summary(minute))

    recurring = tracker.summarize(make_summary(25))
    assert recurring["matching_windows_last_hour"] == 6
    assert recurring["consecutive_matching_windows"] == 6
    assert recurring["continuous_minutes"] == 30
    assert recurring["severity_signal"] == "sustained_multi_window"


def test_alert_engine_injects_historical_correlation_into_window_prompt(tmp_path: Path):
    cfg = make_config(tmp_path)
    context_dir = cfg.context_dir
    context_dir.mkdir()
    (context_dir / "01_environment.md").write_text("env", encoding="utf-8")
    (context_dir / "02_detection_policy.md").write_text("policy", encoding="utf-8")

    client = DummyGroqClient(
        {
            "should_alert": False,
            "severity": "low",
            "confidence": 25,
            "category": "waf_block_rate_anomaly",
            "title": "Low signal WAF block anomaly",
            "summary": "",
            "reasoning": "",
            "recommended_actions": [],
            "dedup_key": "waf|issuing-users",
        }
    )
    loader = ContextLoader(context_dir, max_chars=2000)
    analyzer = Analyzer(cfg, loader, client)  # type: ignore[arg-type]
    engine = AlertEngine(cfg, analyzer)

    def make_batch(start_minute: int) -> WindowBatch:
        observed_at = datetime(2026, 3, 17, 13, start_minute, tzinfo=timezone.utc)
        event = Event(
            log_type="waf",
            action="blocked",
            src_ip=f"27.1.108.{start_minute + 10}",
            uri="/issuing/users",
            method="POST",
            rule_id="ddos-rate-limit",
        )
        return WindowBatch(
            events=[event],
            window_start=observed_at,
            window_end=datetime(2026, 3, 17, 13, start_minute + 5, tzinfo=timezone.utc),
            first_observed_at=observed_at,
            last_observed_at=observed_at,
            flush_reason="window_timeout",
        )

    engine.process_batch(make_batch(0))
    engine.process_batch(make_batch(5))

    assert client.last_messages is not None
    user_message = client.last_messages[1].content
    assert '"historical_correlation"' in user_message
    assert '"matching_windows_last_hour": 2' in user_message
    assert '"consecutive_matching_windows": 2' in user_message


def test_duplicate_alert_suppression(tmp_path: Path):
    cfg = make_config(tmp_path)
    context_dir = cfg.context_dir
    context_dir.mkdir()
    (context_dir / "01_environment.md").write_text("env", encoding="utf-8")

    loader = ContextLoader(context_dir, max_chars=2000)
    payload = {
        "should_alert": True,
        "severity": "high",
        "confidence": 80,
        "category": "test",
        "title": "Test",
        "summary": "",
        "reasoning": "",
        "recommended_actions": [],
        "dedup_key": "dup-key",
    }
    analyzer = Analyzer(cfg, loader, DummyGroqClient(payload))  # type: ignore[arg-type]
    engine = AlertEngine(cfg, analyzer)

    event = Event(log_type="waf", src_ip="1.2.3.4")

    observed_at = datetime(2026, 3, 17, 13, 0, tzinfo=timezone.utc)
    batch = WindowBatch(
        events=[event],
        window_start=observed_at,
        window_end=datetime(2026, 3, 17, 13, 5, tzinfo=timezone.utc),
        first_observed_at=observed_at,
        last_observed_at=observed_at,
        flush_reason="window_timeout",
    )

    result1 = engine.process_batch(batch)
    result2 = engine.process_batch(batch)
    alert1 = result1.alert
    alert2 = result2.alert

    assert alert1 is not None
    assert alert2 is None
    assert result1.usage.total_cost_usd > 0


def test_analyzer_returns_error_outcome_when_llm_fails(tmp_path: Path):
    cfg = make_config(tmp_path)
    context_dir = cfg.context_dir
    context_dir.mkdir()
    (context_dir / "01_environment.md").write_text("env", encoding="utf-8")

    loader = ContextLoader(context_dir, max_chars=2000)
    analyzer = Analyzer(cfg, loader, FailingGroqClient())  # type: ignore[arg-type]
    batch = WindowBatch(
        events=[Event(log_type="waf", src_ip="1.2.3.4")],
        window_start=datetime(2026, 3, 17, 13, 0, tzinfo=timezone.utc),
        window_end=datetime(2026, 3, 17, 13, 5, tzinfo=timezone.utc),
        first_observed_at=datetime(2026, 3, 17, 13, 0, tzinfo=timezone.utc),
        last_observed_at=datetime(2026, 3, 17, 13, 0, tzinfo=timezone.utc),
        flush_reason="window_timeout",
    )

    result = analyzer.analyze_batch(batch)
    assert result.outcome == "error"
    assert result.alert is None


def test_telegram_notifier_disabled_without_credentials(tmp_path: Path):
    cfg = make_config(tmp_path)
    notifier = TelegramNotifier(cfg)
    try:
        assert notifier.enabled is False
    finally:
        notifier.close()


def test_telegram_message_format_for_window_alert():
    alert = Alert.model_validate(
        {
            "event": {
                "window": {
                    "start": "2026-03-17T13:00:00Z",
                    "end": "2026-03-17T13:05:00Z",
                    "aggregated_record_count": 12,
                    "flush_reason": "window_timeout",
                },
                "dominant_log_type": "vpc",
                "historical_correlation": {
                    "lookback_seconds": 3600,
                    "matching_windows_last_hour": 6,
                    "continuous_minutes": 30,
                },
            },
            "analysis": {
                "should_alert": True,
                "severity": "high",
                "confidence": 88,
                "category": "exposed_service",
                "title": "Repeated external access to Redis",
                "summary": "Multiple external sources reached a private Redis port within one batch window.",
                "reasoning": "Sustained external-to-private traffic to a sensitive port exceeded thresholds.",
                "recommended_actions": [
                    "Verify intended exposure.",
                    "Review security groups.",
                ],
                "dedup_key": "vpc|redis|exposed",
            },
            "usage": {
                "request": {
                    "prompt_tokens": 120,
                    "cached_tokens": 0,
                    "completion_tokens": 30,
                    "total_cost_usd": 0.000036,
                },
                "daily": {
                    "total_cost_usd": 0.000120,
                },
            },
        }
    )

    message = format_telegram_message(alert)
    assert "ALERT HIGH 88%" in message
    assert "Repeated external access to Redis" in message
    assert "Window: 2026-03-17T13:00:00Z -> 2026-03-17T13:05:00Z" in message
    assert "reason=window_timeout" in message
    assert "LLM usage: prompt=120 cached=0 completion=30 cost=$0.00003600 today=$0.00012000" in message
    assert "Correlation: 6 matching windows / 30 continuous minutes / 1h" in message
    assert "Dedup: vpc|redis|exposed" in message


def test_no_alert_status_reporter_triggers_after_interval():
    reporter = NoAlertStatusReporter(interval_seconds=3600)
    reporter.reset(now=datetime(2026, 3, 17, 13, 0, tzinfo=timezone.utc))

    assert reporter.should_send(
        now=datetime(2026, 3, 17, 13, 59, 59, tzinfo=timezone.utc)
    ) is False
    assert reporter.should_send(
        now=datetime(2026, 3, 17, 14, 0, tzinfo=timezone.utc)
    ) is True


def test_no_alert_status_message_format():
    summary = {
        "period": {
            "start": "2026-03-17T13:00:00Z",
            "end": "2026-03-17T14:00:00Z",
        },
        "batches_analyzed": 12,
        "event_count": 34,
        "aggregated_record_count": 56,
        "log_type_counts": {"vpc": 40, "waf": 16},
        "action_counts": {"accept": 20, "block": 36},
        "top_source_ips": [{"ip": "1.1.1.1", "count": 10}],
        "top_destination_ips": [{"ip": "10.0.0.5", "count": 8}],
        "analysis": {
            "title": "Interval appears operationally normal",
            "summary": "Required telemetry was present and no important alert-worthy behavior was identified.",
        },
        "llm_usage": {
            "calls": 12,
            "prompt_tokens": 1200,
            "cached_tokens": 100,
            "completion_tokens": 240,
            "total_tokens": 1440,
            "total_cost_usd": 0.00123,
        },
        "daily_llm_usage": {
            "total_cost_usd": 0.00456,
        },
    }

    message = format_no_alert_status_message(summary)
    assert "STATUS No important alerts in interval" in message
    assert "System state: normal." in message
    assert "Period: 2026-03-17T13:00:00Z -> 2026-03-17T14:00:00Z" in message
    assert "Processed: batches=12 | events=34 | aggregated_records=56" in message
    assert "Assessment: Interval appears operationally normal" in message
    assert "AI summary: Required telemetry was present" in message
    assert "LLM cost: interval=$0.00123000 today=$0.00456000" in message
    assert "LLM tokens: calls=12 prompt=1200 cached=100 completion=240" in message
    assert "Log types: vpc=40, waf=16" in message


def test_cost_tracker_records_daily_totals(tmp_path: Path):
    tracker = ModelCostTracker(
        report_path=tmp_path / "model_usage_costs.txt",
        input_cost_per_million=0.15,
        cached_input_cost_per_million=0.075,
        output_cost_per_million=0.60,
    )
    recorded_at = datetime(2026, 3, 17, 13, 0, tzinfo=timezone.utc)
    costs = tracker.estimate_costs(prompt_tokens=1000, cached_tokens=200, completion_tokens=300)
    summary = tracker.record_call(
        ModelCallRecord(
            recorded_at=recorded_at,
            model="openai/gpt-oss-120b",
            status="success",
            prompt_tokens=1000,
            cached_tokens=200,
            completion_tokens=300,
            total_tokens=1300,
            input_cost_usd=costs["input_cost_usd"],
            cached_input_cost_usd=costs["cached_input_cost_usd"],
            output_cost_usd=costs["output_cost_usd"],
            total_cost_usd=costs["total_cost_usd"],
            http_status=200,
        )
    )

    report = (tmp_path / "model_usage_costs.txt").read_text(encoding="utf-8")
    assert summary["calls"] == 1
    assert summary["prompt_tokens"] == 1000
    assert "DAY\t2026-03-17" in report
    assert "CALL\t2026-03-17T13:00:00Z" in report


def test_no_alert_status_reporter_summary_has_log_counts_only():
    reporter = NoAlertStatusReporter(interval_seconds=3600)
    reporter.reset(now=datetime(2026, 3, 17, 13, 0, tzinfo=timezone.utc))

    summary = reporter.build_summary(now=datetime(2026, 3, 17, 14, 0, tzinfo=timezone.utc))
    assert "log_type_counts" in summary
    assert "missing_required_log_types" not in summary
    assert "has_required_telemetry" not in summary


def test_log_follower_reads_from_beginning_on_first_open(tmp_path: Path):
    path = tmp_path / "log.jsonl"
    path.write_text('{"log_type":"waf","src_ip":"1.2.3.4"}\n', encoding="utf-8")
    follower = LogFollower(path, poll_interval=0.01, start_position="beginning")

    stream = follower.entries()
    event = next(stream)
    assert event is not None
    assert event.log_type == "waf"


def test_log_follower_skips_existing_lines_when_starting_at_end(tmp_path: Path):
    path = tmp_path / "log.jsonl"
    path.write_text('{"log_type":"waf","src_ip":"1.2.3.4"}\n', encoding="utf-8")
    follower = LogFollower(path, poll_interval=0.01, start_position="end")

    stream = follower.entries()
    first = next(stream)
    assert first is None

    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"log_type":"vpc","src_ip":"2.2.2.2"}\n')

    second = next(stream)
    assert second is not None
    assert second.log_type == "vpc"


def test_failed_batch_queue_persists_and_requeues(tmp_path: Path):
    batch = WindowBatch(
        events=[Event(log_type="waf", src_ip="1.2.3.4")],
        window_start=datetime(2026, 3, 17, 13, 0, tzinfo=timezone.utc),
        window_end=datetime(2026, 3, 17, 13, 5, tzinfo=timezone.utc),
        first_observed_at=datetime(2026, 3, 17, 13, 0, tzinfo=timezone.utc),
        last_observed_at=datetime(2026, 3, 17, 13, 0, tzinfo=timezone.utc),
        flush_reason="window_timeout",
    )
    queue = FailedBatchQueue(
        path=tmp_path / "failed_batches.jsonl",
        base_delay_seconds=30,
        max_delay_seconds=900,
        max_attempts=3,
    )

    queue.enqueue(batch, reason="analysis_error")
    item = queue.pop_due(now=datetime.now(timezone.utc))
    assert item is not None
    assert item.batch.events[0].log_type == "waf"
    kept = queue.requeue(
        item,
        reason="analysis_error",
        now=datetime(2026, 3, 17, 13, 0, tzinfo=timezone.utc),
    )
    assert kept is True

    reloaded = FailedBatchQueue(
        path=tmp_path / "failed_batches.jsonl",
        base_delay_seconds=30,
        max_delay_seconds=900,
        max_attempts=3,
    )
    assert reloaded.size() == 1


def test_analyzer_can_raise_telemetry_gap_from_interval_summary(tmp_path: Path):
    cfg = make_config(tmp_path)
    context_dir = cfg.context_dir
    context_dir.mkdir()
    (context_dir / "01_environment.md").write_text("env", encoding="utf-8")
    (context_dir / "02_detection_policy.md").write_text("policy", encoding="utf-8")
    (context_dir / "05_response_playbooks.md").write_text("playbook", encoding="utf-8")

    loader = ContextLoader(context_dir, max_chars=2000)
    payload = {
        "should_alert": True,
        "severity": "high",
        "confidence": 92,
        "category": "telemetry_gap",
        "title": "Missing AWS WAF telemetry in interval",
        "summary": "No WAF logs were observed during the interval while VPC telemetry remained present.",
        "reasoning": "The interval summary shows a visibility gap for a required telemetry source.",
        "recommended_actions": ["Verify WAF log delivery."],
        "dedup_key": "telemetry_gap|waf",
    }
    analyzer = Analyzer(cfg, loader, DummyGroqClient(payload))  # type: ignore[arg-type]

    result = analyzer.analyze_status_summary(
        {
            "period": {
                "start": "2026-03-17T13:00:00Z",
                "end": "2026-03-17T14:00:00Z",
            },
            "log_type_counts": {"vpc": 100},
        }
    )

    assert result.alert is not None
    assert result.analysis is not None
    assert result.analysis.category == "telemetry_gap"
    assert result.alert.event["summary_kind"] == "interval_status"


def test_groq_payload_uses_strict_schema_for_gpt_oss(tmp_path: Path):
    cfg = make_config(tmp_path)
    cfg.groq_model = "openai/gpt-oss-120b"
    client = GroqClient(cfg)

    try:
        payload = client._build_payload([{"role": "user", "content": "x"}])  # type: ignore[list-item]
    finally:
        client.close()

    assert payload["response_format"]["type"] == "json_schema"
    assert payload["response_format"]["json_schema"]["schema"] == MODEL_ANALYSIS_JSON_SCHEMA
    assert payload["response_format"]["json_schema"]["strict"] is True
    assert payload["include_reasoning"] is False
    assert payload["reasoning_effort"] == "low"
    assert payload["max_completion_tokens"] == 1024


def test_groq_payload_uses_json_object_for_other_models(tmp_path: Path):
    cfg = make_config(tmp_path)
    cfg.groq_model = "llama-3.1-70b-versatile"
    client = GroqClient(cfg)

    try:
        payload = client._build_payload([{"role": "user", "content": "x"}])  # type: ignore[list-item]
    finally:
        client.close()

    assert payload["response_format"] == {"type": "json_object"}
    assert "include_reasoning" not in payload
    assert "reasoning_effort" not in payload


def test_groq_payload_fallback_uses_json_object_for_gpt_oss(tmp_path: Path):
    cfg = make_config(tmp_path)
    cfg.groq_model = "openai/gpt-oss-120b"
    client = GroqClient(cfg)

    try:
        payload = client._build_payload(  # type: ignore[list-item]
            [{"role": "user", "content": "x"}],
            strict_json_schema=False,
        )
    finally:
        client.close()

    assert payload["response_format"] == {"type": "json_object"}
