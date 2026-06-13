from __future__ import annotations

import logging

from .batching import WindowBatch, build_window_summary, representative_event_for_batch
from .config import AppConfig
from .context_loader import ContextLoader
from .models import (
    Alert,
    BatchAnalysisResult,
    Event,
    ModelAnalysis,
    ModelUsage,
    parse_model_analysis,
)
from .prompt_builder import build_status_messages, build_window_messages
from .groq_client import GroqClient

logger = logging.getLogger(__name__)


class Analyzer:
    """High-level window analysis pipeline combining context, prompting and Groq client."""

    def __init__(
        self, config: AppConfig, context_loader: ContextLoader, groq_client: GroqClient
    ) -> None:
        self._config = config
        self._context_loader = context_loader
        self._groq_client = groq_client

    def analyze_batch(self, batch: WindowBatch) -> BatchAnalysisResult:
        """Analyze a time window of events and return alert plus usage details."""

        if not batch.events:
            return BatchAnalysisResult(
                outcome="no_alert",
                alert=None,
                usage=ModelUsage(model=self._groq_client.model_name),
            )

        representative_event = representative_event_for_batch(batch)
        context = self._context_loader.build_context(representative_event)
        window_summary = build_window_summary(
            batch, configured_window_seconds=self._config.batch_window_seconds
        )
        return self._analyze_window_summary(window_summary, context)

    def analyze_window_summary(
        self, window_summary: dict, representative_event: Event
    ) -> BatchAnalysisResult:
        """Analyze a precomputed window summary, optionally enriched with correlation context."""

        context = self._context_loader.build_context(representative_event)
        return self._analyze_window_summary(window_summary, context)

    def _analyze_window_summary(
        self, window_summary: dict, context: str
    ) -> BatchAnalysisResult:
        model_name = getattr(self._groq_client, "model_name", None)
        messages = build_window_messages(window_summary, context, model_name)
        chat_result = self._groq_client.chat(messages)
        raw = chat_result.content
        if raw is None:
            logger.error("Groq window analysis failed; skipping batch.")
            return BatchAnalysisResult(
                outcome="error",
                alert=None,
                usage=chat_result.usage,
                daily_totals=chat_result.daily_totals,
            )

        try:
            analysis: ModelAnalysis = parse_model_analysis(raw)
        except Exception:
            logger.exception("Failed to parse model analysis; skipping batch.")
            return BatchAnalysisResult(
                outcome="error",
                alert=None,
                usage=chat_result.usage,
                daily_totals=chat_result.daily_totals,
            )

        if not analysis.should_alert:
            return BatchAnalysisResult(
                outcome="no_alert",
                alert=None,
                analysis=analysis,
                usage=chat_result.usage,
                daily_totals=chat_result.daily_totals,
            )

        alert = Alert(
            event=window_summary,
            analysis=analysis,
            usage={
                "request": chat_result.usage.model_dump(mode="json"),
                "daily": chat_result.daily_totals,
            },
        )
        return BatchAnalysisResult(
            outcome="alert",
            alert=alert,
            analysis=analysis,
            usage=chat_result.usage,
            daily_totals=chat_result.daily_totals,
        )

    def analyze_status_summary(self, summary: dict) -> BatchAnalysisResult:
        """Analyze a reporting interval summary and decide whether it warrants an alert."""

        context = self._context_loader.build_full_context()
        model_name = getattr(self._groq_client, "model_name", None)
        messages = build_status_messages(summary, context, model_name)
        chat_result = self._groq_client.chat(messages)
        raw = chat_result.content
        if raw is None:
            logger.error("Groq interval status analysis failed; treating summary as informational.")
            return BatchAnalysisResult(
                outcome="error",
                alert=None,
                usage=chat_result.usage,
                daily_totals=chat_result.daily_totals,
            )

        try:
            analysis: ModelAnalysis = parse_model_analysis(raw)
        except Exception:
            logger.exception("Failed to parse interval status analysis; treating summary as informational.")
            return BatchAnalysisResult(
                outcome="error",
                alert=None,
                usage=chat_result.usage,
                daily_totals=chat_result.daily_totals,
            )

        if not analysis.should_alert:
            return BatchAnalysisResult(
                outcome="no_alert",
                alert=None,
                analysis=analysis,
                usage=chat_result.usage,
                daily_totals=chat_result.daily_totals,
            )

        alert = Alert(
            event={"summary_kind": "interval_status", **summary},
            analysis=analysis,
            usage={
                "request": chat_result.usage.model_dump(mode="json"),
                "daily": chat_result.daily_totals,
            },
        )
        return BatchAnalysisResult(
            outcome="alert",
            alert=alert,
            analysis=analysis,
            usage=chat_result.usage,
            daily_totals=chat_result.daily_totals,
        )


__all__ = ["Analyzer"]
