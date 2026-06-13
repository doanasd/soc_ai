from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv  # type: ignore[import-not-found]


@dataclass(slots=True)
class AppConfig:
    """Application configuration loaded from environment variables."""

    log_input_path: Path
    alert_output_path: Path
    context_dir: Path
    failed_batch_spool_path: Path
    log_start_position: Literal["beginning", "end"]

    groq_api_key: str
    groq_model: str
    groq_timeout_seconds: float
    groq_max_retries: int
    groq_max_completion_tokens: int
    groq_input_cost_per_million: float
    groq_cached_input_cost_per_million: float
    groq_output_cost_per_million: float
    model_usage_report_path: Path

    telegram_bot_token: str
    telegram_chat_id: str
    telegram_timeout_seconds: float
    no_alert_summary_interval_seconds: int
    retry_failed_batches: bool
    retry_base_delay_seconds: int
    retry_max_delay_seconds: int
    retry_max_attempts: int

    batch_window_seconds: int
    batch_idle_timeout_seconds: int
    poll_interval_seconds: float
    alert_suppression_ttl_seconds: int
    correlation_lookback_seconds: int
    max_context_chars: int

    investigation_queue_path: Path

    log_level: int


def _get_log_level(value: str | None) -> int:
    level = (value or "INFO").upper()
    numeric = getattr(logging, level, logging.INFO)
    return numeric if isinstance(numeric, int) else logging.INFO


def _default_model_pricing(model_name: str) -> tuple[float, float, float]:
    defaults = {
        "openai/gpt-oss-120b": (0.15, 0.075, 0.60),
        "openai/gpt-oss-20b": (0.075, 0.0375, 0.30),
    }
    return defaults.get(model_name, (0.0, 0.0, 0.0))


def load_config(env_file: str | None = ".env") -> AppConfig:
    """Load configuration from environment variables and optional .env file."""

    if env_file:
        load_dotenv(env_file)

    log_input_path = Path(os.getenv("LOG_INPUT_PATH", "./log_dedup.json")).expanduser()
    alert_output_path = Path(
        os.getenv("ALERT_OUTPUT_PATH", "./data/alerts.jsonl")
    ).expanduser()
    context_dir = Path(os.getenv("CONTEXT_DIR", "./context")).expanduser()
    failed_batch_spool_path = Path(
        os.getenv("FAILED_BATCH_SPOOL_PATH", "./data/failed_batches.jsonl")
    ).expanduser()
    raw_log_start_position = (os.getenv("LOG_START_POSITION", "end") or "end").strip().lower()
    log_start_position: Literal["beginning", "end"] = (
        "beginning" if raw_log_start_position == "beginning" else "end"
    )

    groq_api_key = os.getenv("GROQ_API_KEY", "")
    groq_model = os.getenv("GROQ_MODEL", "llama-3.1-70b-versatile")
    groq_timeout_seconds = float(os.getenv("GROQ_TIMEOUT_SECONDS", "15"))
    groq_max_retries = int(os.getenv("GROQ_MAX_RETRIES", "3"))
    groq_max_completion_tokens = int(os.getenv("GROQ_MAX_COMPLETION_TOKENS", "1024"))
    (
        default_input_cost,
        default_cached_input_cost,
        default_output_cost,
    ) = _default_model_pricing(groq_model)
    groq_input_cost_per_million = float(
        os.getenv("GROQ_INPUT_COST_PER_MILLION", str(default_input_cost))
    )
    groq_cached_input_cost_per_million = float(
        os.getenv("GROQ_CACHED_INPUT_COST_PER_MILLION", str(default_cached_input_cost))
    )
    groq_output_cost_per_million = float(
        os.getenv("GROQ_OUTPUT_COST_PER_MILLION", str(default_output_cost))
    )
    model_usage_report_path = Path(
        os.getenv("MODEL_USAGE_REPORT_PATH", "./data/model_usage_costs.txt")
    ).expanduser()

    telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    telegram_chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
    telegram_timeout_seconds = float(os.getenv("TELEGRAM_TIMEOUT_SECONDS", "10"))
    no_alert_summary_interval_seconds = int(
        os.getenv("NO_ALERT_SUMMARY_INTERVAL_SECONDS", "3600")
    )
    retry_failed_batches = (os.getenv("RETRY_FAILED_BATCHES", "true").strip().lower() != "false")
    retry_base_delay_seconds = int(os.getenv("RETRY_BASE_DELAY_SECONDS", "30"))
    retry_max_delay_seconds = int(os.getenv("RETRY_MAX_DELAY_SECONDS", "900"))
    retry_max_attempts = int(os.getenv("RETRY_MAX_ATTEMPTS", "8"))

    batch_window_seconds = int(os.getenv("BATCH_WINDOW_SECONDS", "300"))
    batch_idle_timeout_seconds = int(
        os.getenv("BATCH_IDLE_TIMEOUT_SECONDS", str(batch_window_seconds))
    )
    poll_interval_seconds = float(os.getenv("POLL_INTERVAL_SECONDS", "1.0"))
    alert_suppression_ttl_seconds = int(
        os.getenv("ALERT_SUPPRESSION_TTL_SECONDS", "300")
    )
    correlation_lookback_seconds = int(
        os.getenv("CORRELATION_LOOKBACK_SECONDS", "3600")
    )
    max_context_chars = int(os.getenv("MAX_CONTEXT_CHARS", "8000"))

    investigation_queue_path = Path(
        os.getenv("INVESTIGATION_QUEUE_PATH", "../threat_hunter/data/pending_investigations.jsonl")
    ).expanduser()

    log_level = _get_log_level(os.getenv("LOG_LEVEL"))

    return AppConfig(
        log_input_path=log_input_path,
        alert_output_path=alert_output_path,
        context_dir=context_dir,
        failed_batch_spool_path=failed_batch_spool_path,
        log_start_position=log_start_position,
        groq_api_key=groq_api_key,
        groq_model=groq_model,
        groq_timeout_seconds=groq_timeout_seconds,
        groq_max_retries=groq_max_retries,
        groq_max_completion_tokens=groq_max_completion_tokens,
        groq_input_cost_per_million=groq_input_cost_per_million,
        groq_cached_input_cost_per_million=groq_cached_input_cost_per_million,
        groq_output_cost_per_million=groq_output_cost_per_million,
        model_usage_report_path=model_usage_report_path,
        telegram_bot_token=telegram_bot_token,
        telegram_chat_id=telegram_chat_id,
        telegram_timeout_seconds=telegram_timeout_seconds,
        no_alert_summary_interval_seconds=no_alert_summary_interval_seconds,
        retry_failed_batches=retry_failed_batches,
        retry_base_delay_seconds=retry_base_delay_seconds,
        retry_max_delay_seconds=retry_max_delay_seconds,
        retry_max_attempts=retry_max_attempts,
        batch_window_seconds=batch_window_seconds,
        batch_idle_timeout_seconds=batch_idle_timeout_seconds,
        poll_interval_seconds=poll_interval_seconds,
        alert_suppression_ttl_seconds=alert_suppression_ttl_seconds,
        correlation_lookback_seconds=correlation_lookback_seconds,
        investigation_queue_path=investigation_queue_path,
        max_context_chars=max_context_chars,
        log_level=log_level,
    )


__all__ = ["AppConfig", "load_config"]
