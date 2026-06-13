from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv  # type: ignore[import-not-found]


@dataclass(slots=True)
class HuntConfig:
    """Configuration for Threat Hunter loaded from environment variables."""

    # MCP & OpenSearch
    mcp_server_url: str
    mcp_tool_name: str
    opensearch_index_pattern: str

    # Schedule
    hunt_interval_seconds: int
    hunt_lookback_hours: int

    # LLM (Groq)
    groq_api_key: str
    groq_model: str
    groq_max_tokens: int
    groq_timeout_seconds: float

    # Hunt Agent Limits
    max_tool_calls_per_hypothesis: int
    max_log_results_per_query: int

    # Output
    findings_output_path: Path
    baseline_path: Path

    # Telegram
    telegram_bot_token: str
    telegram_chat_id: str
    telegram_timeout_seconds: float

    # Logging
    log_level: int

    # Investigation Queue (AI Alert bridge)
    investigation_queue_path: Path
    investigation_queue_poll_seconds: float


def _get_log_level(value: str | None) -> int:
    level = (value or "INFO").upper()
    numeric = getattr(logging, level, logging.INFO)
    return numeric if isinstance(numeric, int) else logging.INFO


def load_config(env_file: str | None = ".env") -> HuntConfig:
    """Load configuration from environment variables and optional .env file."""

    if env_file:
        load_dotenv(env_file)

    return HuntConfig(
        # MCP & OpenSearch
        mcp_server_url=os.getenv("MCP_SERVER_URL", "http://10.10.10.20:9900/mcp/"),
        mcp_tool_name=os.getenv("MCP_TOOL_NAME", "SearchIndexTool"),
        opensearch_index_pattern=os.getenv("OPENSEARCH_INDEX_PATTERN", "soc-logs-*"),

        # Schedule
        hunt_interval_seconds=int(os.getenv("HUNT_INTERVAL_SECONDS", "21600")),
        hunt_lookback_hours=int(os.getenv("HUNT_LOOKBACK_HOURS", "24")),

        # LLM (Groq)
        groq_api_key=os.getenv("HUNT_GROQ_API_KEY", ""),
        groq_model=os.getenv("HUNT_GROQ_MODEL", "llama3-70b-8192"),
        groq_max_tokens=int(os.getenv("HUNT_GROQ_MAX_TOKENS", "4096")),
        groq_timeout_seconds=float(os.getenv("HUNT_GROQ_TIMEOUT_SECONDS", "60")),

        # Hunt Agent Limits
        max_tool_calls_per_hypothesis=int(os.getenv("MAX_TOOL_CALLS_PER_HYPOTHESIS", "3")),
        max_log_results_per_query=int(os.getenv("MAX_LOG_RESULTS_PER_QUERY", "100")),

        # Output
        findings_output_path=Path(
            os.getenv("HUNT_FINDINGS_OUTPUT_PATH", "./data/hunt_findings.jsonl")
        ).expanduser(),
        baseline_path=Path(
            os.getenv("HUNT_BASELINE_PATH", "./data/baseline.json")
        ).expanduser(),

        # Telegram
        telegram_bot_token=os.getenv("HUNT_TELEGRAM_BOT_TOKEN", ""),
        telegram_chat_id=os.getenv("HUNT_TELEGRAM_CHAT_ID", ""),
        telegram_timeout_seconds=float(os.getenv("HUNT_TELEGRAM_TIMEOUT_SECONDS", "10")),

        # Logging
        log_level=_get_log_level(os.getenv("LOG_LEVEL")),

        # Investigation Queue (AI Alert bridge)
        investigation_queue_path=Path(
            os.getenv("INVESTIGATION_QUEUE_PATH", "./data/pending_investigations.jsonl")
        ).expanduser(),
        investigation_queue_poll_seconds=float(
            os.getenv("INVESTIGATION_QUEUE_POLL_SECONDS", "10")
        ),
    )


__all__ = ["HuntConfig", "load_config"]
