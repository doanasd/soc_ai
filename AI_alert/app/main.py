from __future__ import annotations

import logging
import signal
from datetime import datetime, timezone
from typing import Optional

from .alert_engine import AlertEngine
from .analyzer import Analyzer
from .batching import EventBatcher
from .config import AppConfig, load_config
from .context_loader import ContextLoader
from .groq_client import GroqClient
from .investigation_queue import write_investigation_request
from .reader import LogFollower
from .retry_queue import FailedBatchQueue
from .status_reporter import NoAlertStatusReporter
from .writers.jsonl_writer import append_jsonl
from .writers.stdout_writer import print_summary
from .writers.telegram_writer import TelegramNotifier


logger = logging.getLogger(__name__)


def configure_logging(level: int) -> None:
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


_shutdown = False


def _handle_signal(signum, frame) -> None:  # type: ignore[no-untyped-def]
    global _shutdown
    logger.info("Received signal %s, shutting down gracefully.", signum)
    _shutdown = True


def _emit_alert(config: AppConfig, alert, telegram: TelegramNotifier) -> None:  # type: ignore[no-untyped-def]
    alert_data = alert.model_dump(mode="json")
    append_jsonl(config.alert_output_path, alert_data)
    print_summary(alert)
    telegram.send_alert(alert)

    # ── Bridge to Threat Hunter: queue investigation request ─────────
    write_investigation_request(config.investigation_queue_path, alert_data)


def _record_result(
    config: AppConfig,
    result,
    batch,
    reporter: NoAlertStatusReporter,
    telegram: TelegramNotifier,
    retry_queue: FailedBatchQueue,
) -> None:  # type: ignore[no-untyped-def]
    if result.outcome == "alert" and result.alert is not None:
        _emit_alert(config, result.alert, telegram)
        reporter.record_alert()
        return

    if result.outcome == "error":
        if config.retry_failed_batches:
            retry_queue.enqueue(batch, reason="analysis_error")
        return

    reporter.record_batch(batch, result.usage)


def _process_retry_queue(
    config: AppConfig,
    engine: AlertEngine,
    reporter: NoAlertStatusReporter,
    telegram: TelegramNotifier,
    retry_queue: FailedBatchQueue,
) -> None:
    if not config.retry_failed_batches:
        return

    item = retry_queue.pop_due()
    if item is None:
        return

    result = engine.process_batch(item.batch)
    if result.outcome == "error":
        kept = retry_queue.requeue(item, reason="analysis_error")
        if not kept:
            logger.error(
                "Dropping failed batch after max retry attempts. window_start=%s window_end=%s",
                item.batch.window_start.isoformat(),
                item.batch.window_end.isoformat(),
            )
        return

    if result.outcome == "alert" and result.alert is not None:
        _emit_alert(config, result.alert, telegram)
        reporter.record_alert()


def _maybe_send_no_alert_status(
    config: AppConfig,
    telegram: TelegramNotifier,
    reporter: NoAlertStatusReporter,
    analyzer: Analyzer,
    groq_client: GroqClient,
    now: Optional[datetime] = None,
) -> None:
    if not telegram.enabled:
        return

    current_time = now or datetime.now(timezone.utc)
    if reporter.should_send(current_time):
        summary = reporter.build_summary(current_time)
        result = analyzer.analyze_status_summary(summary)
        interval_usage = summary.get("llm_usage") or {}
        interval_usage["calls"] = int(interval_usage.get("calls", 0)) + int(result.usage.attempts)
        interval_usage["prompt_tokens"] = int(interval_usage.get("prompt_tokens", 0)) + int(
            result.usage.prompt_tokens
        )
        interval_usage["cached_tokens"] = int(interval_usage.get("cached_tokens", 0)) + int(
            result.usage.cached_tokens
        )
        interval_usage["completion_tokens"] = int(
            interval_usage.get("completion_tokens", 0)
        ) + int(result.usage.completion_tokens)
        interval_usage["total_tokens"] = int(interval_usage.get("total_tokens", 0)) + int(
            result.usage.total_tokens
        )
        interval_usage["total_cost_usd"] = float(
            interval_usage.get("total_cost_usd", 0.0)
        ) + float(result.usage.total_cost_usd)
        summary["llm_usage"] = interval_usage
        summary["daily_llm_usage"] = result.daily_totals or groq_client.current_daily_totals
        if result.analysis is not None:
            summary["analysis"] = result.analysis.model_dump(mode="json")

        if result.alert is not None:
            _emit_alert(config, result.alert, telegram)
        else:
            telegram.send_status_summary(summary)
        reporter.reset(current_time)


def run(config: Optional[AppConfig] = None) -> None:
    """Entry point for the streaming SOC triage service."""

    if config is None:
        config = load_config()

    configure_logging(config.log_level)
    logger.info("Starting SOC AI alert service.")

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    context_loader = ContextLoader(config.context_dir, config.max_context_chars)
    groq_client = GroqClient(config)
    telegram = TelegramNotifier(config)
    reporter = NoAlertStatusReporter(config.no_alert_summary_interval_seconds)
    analyzer = Analyzer(config, context_loader, groq_client)
    engine = AlertEngine(config, analyzer)
    batcher = EventBatcher(config.batch_window_seconds)
    retry_queue = FailedBatchQueue(
        path=config.failed_batch_spool_path,
        base_delay_seconds=config.retry_base_delay_seconds,
        max_delay_seconds=config.retry_max_delay_seconds,
        max_attempts=config.retry_max_attempts,
    )
    follower = LogFollower(
        config.log_input_path,
        config.poll_interval_seconds,
        start_position=config.log_start_position,
    )

    try:
        for entry in follower.entries():
            if _shutdown:
                break

            _process_retry_queue(config, engine, reporter, telegram, retry_queue)
            _maybe_send_no_alert_status(config, telegram, reporter, analyzer, groq_client)

            if entry is None:
                if batcher.should_flush(
                    idle_timeout_seconds=config.batch_idle_timeout_seconds
                ):
                    ready_batch = batcher.flush(flush_reason="idle_timeout")
                    if ready_batch is not None:
                        result = engine.process_batch(ready_batch)
                        _record_result(
                            config,
                            result,
                            ready_batch,
                            reporter,
                            telegram,
                            retry_queue,
                        )
                continue

            ready_batch = batcher.add(entry)
            if ready_batch is not None:
                result = engine.process_batch(ready_batch)
                _record_result(
                    config,
                    result,
                    ready_batch,
                    reporter,
                    telegram,
                    retry_queue,
                )

            if batcher.should_flush(
                idle_timeout_seconds=config.batch_idle_timeout_seconds
            ):
                ready_batch = batcher.flush(flush_reason="window_timeout")
                if ready_batch is not None:
                    result = engine.process_batch(ready_batch)
                    _record_result(
                        config,
                        result,
                        ready_batch,
                        reporter,
                        telegram,
                        retry_queue,
                    )

    finally:
        if batcher.has_pending():
            ready_batch = batcher.flush(flush_reason="shutdown")
            if ready_batch is not None:
                result = engine.process_batch(ready_batch)
                _record_result(
                    config,
                    result,
                    ready_batch,
                    reporter,
                    telegram,
                    retry_queue,
                )
        _maybe_send_no_alert_status(config, telegram, reporter, analyzer, groq_client)
        telegram.close()
        groq_client.close()
        logger.info("Service stopped.")


if __name__ == "__main__":
    run()
