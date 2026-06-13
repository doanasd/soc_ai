from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx  # type: ignore[import-not-found]

from .config import AppConfig
from .cost_tracker import ModelCallRecord, ModelCostTracker
from .models import (
    GroqChatResult,
    GroqMessage,
    GroqRequest,
    GroqResponse,
    MODEL_ANALYSIS_JSON_SCHEMA,
    ModelUsage,
)
from .prompt_builder import is_gpt_oss_model

logger = logging.getLogger(__name__)


class GroqClient:
    """Thin wrapper around the Groq chat completion API with retries and usage accounting."""

    def __init__(self, config: AppConfig) -> None:
        if not config.groq_api_key:
            logger.warning("GROQ_API_KEY is empty; analyzer will be effectively disabled.")
        self._config = config
        self._base_url = "https://api.groq.com/openai/v1"
        self._client = httpx.Client(
            base_url=self._base_url,
            headers={
                "Authorization": f"Bearer {config.groq_api_key}",
                "Content-Type": "application/json",
            },
            timeout=config.groq_timeout_seconds,
        )
        self._cost_tracker = ModelCostTracker(
            report_path=config.model_usage_report_path,
            input_cost_per_million=config.groq_input_cost_per_million,
            cached_input_cost_per_million=config.groq_cached_input_cost_per_million,
            output_cost_per_million=config.groq_output_cost_per_million,
        )

    def close(self) -> None:
        self._client.close()

    @property
    def model_name(self) -> str:
        return self._config.groq_model

    @property
    def current_daily_totals(self) -> Dict[str, Any]:
        return self._cost_tracker.current_day_summary()

    def _is_gpt_oss(self) -> bool:
        return is_gpt_oss_model(self._config.groq_model)

    def _supports_strict_json_schema(self) -> bool:
        return self._is_gpt_oss()

    def _build_payload(
        self, messages: List[GroqMessage], strict_json_schema: bool = True
    ) -> Dict[str, Any]:
        response_format: Dict[str, Any] = {"type": "json_object"}
        if strict_json_schema and self._supports_strict_json_schema():
            response_format = {
                "type": "json_schema",
                "json_schema": {
                    "name": "soc_alert_analysis",
                    "schema": MODEL_ANALYSIS_JSON_SCHEMA,
                    "strict": True,
                },
            }

        request = GroqRequest(
            model=self._config.groq_model,
            messages=messages,
            max_completion_tokens=self._config.groq_max_completion_tokens,
            reasoning_effort="low" if self._is_gpt_oss() else None,
            include_reasoning=False if self._is_gpt_oss() else None,
            response_format=response_format,
        )
        return request.model_dump(mode="json", exclude_none=True)

    @staticmethod
    def _should_fallback_to_json_object(status_code: int, body: str) -> bool:
        return status_code == 400 and "json_validate_failed" in body

    def _empty_usage(self) -> ModelUsage:
        return ModelUsage(model=self._config.groq_model)

    def _usage_from_response(self, groq_resp: GroqResponse, success: bool) -> ModelUsage:
        usage = groq_resp.usage
        prompt_tokens = int(usage.prompt_tokens if usage is not None else 0)
        completion_tokens = int(usage.completion_tokens if usage is not None else 0)
        total_tokens = int(
            usage.total_tokens if usage is not None else prompt_tokens + completion_tokens
        )
        cached_tokens = 0
        if usage is not None and usage.prompt_tokens_details is not None:
            cached_tokens = int(usage.prompt_tokens_details.cached_tokens)

        costs = self._cost_tracker.estimate_costs(
            prompt_tokens=prompt_tokens,
            cached_tokens=cached_tokens,
            completion_tokens=completion_tokens,
        )
        return ModelUsage(
            model=self._config.groq_model,
            attempts=1,
            successful_calls=1 if success else 0,
            failed_calls=0 if success else 1,
            prompt_tokens=prompt_tokens,
            cached_tokens=cached_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            input_cost_usd=costs["input_cost_usd"],
            cached_input_cost_usd=costs["cached_input_cost_usd"],
            output_cost_usd=costs["output_cost_usd"],
            total_cost_usd=costs["total_cost_usd"],
        )

    def _record_call(
        self,
        status: str,
        usage: ModelUsage,
        http_status: Optional[int] = None,
    ) -> Dict[str, Any]:
        return self._cost_tracker.record_call(
            ModelCallRecord(
                recorded_at=datetime.now(timezone.utc),
                model=usage.model,
                status=status,
                prompt_tokens=usage.prompt_tokens,
                cached_tokens=usage.cached_tokens,
                completion_tokens=usage.completion_tokens,
                total_tokens=usage.total_tokens,
                input_cost_usd=usage.input_cost_usd,
                cached_input_cost_usd=usage.cached_input_cost_usd,
                output_cost_usd=usage.output_cost_usd,
                total_cost_usd=usage.total_cost_usd,
                http_status=http_status,
            )
        )

    def chat(self, messages: List[GroqMessage]) -> GroqChatResult:
        """Send chat completion request and return parsed JSON content plus usage/cost info."""

        if not self._config.groq_api_key:
            logger.error("GROQ_API_KEY not configured; skipping LLM call.")
            return GroqChatResult(
                content=None,
                usage=self._empty_usage(),
                daily_totals=self.current_daily_totals,
            )

        use_strict_json_schema = self._supports_strict_json_schema()
        aggregate_usage = self._empty_usage()
        daily_totals = self.current_daily_totals

        backoff = 1.0
        for attempt in range(1, self._config.groq_max_retries + 1):
            payload = self._build_payload(
                messages, strict_json_schema=use_strict_json_schema
            )
            try:
                response = self._client.post("/chat/completions", json=payload)
                response.raise_for_status()
                data = response.json()

                groq_resp = GroqResponse.model_validate(data)
                call_usage = self._usage_from_response(groq_resp, success=True)

                if not groq_resp.choices:
                    logger.error("Groq response has no choices: %s", data)
                    call_usage.successful_calls = 0
                    call_usage.failed_calls = 1
                    aggregate_usage.add(call_usage)
                    daily_totals = self._record_call(
                        "empty_choices", call_usage, http_status=response.status_code
                    )
                    return GroqChatResult(
                        content=None, usage=aggregate_usage, daily_totals=daily_totals
                    )

                content = groq_resp.choices[0].message.content
                try:
                    parsed = json.loads(content)
                except json.JSONDecodeError:
                    logger.exception("Failed to decode Groq JSON content: %s", content)
                    call_usage.successful_calls = 0
                    call_usage.failed_calls = 1
                    aggregate_usage.add(call_usage)
                    daily_totals = self._record_call(
                        "json_decode_error",
                        call_usage,
                        http_status=response.status_code,
                    )
                    return GroqChatResult(
                        content=None, usage=aggregate_usage, daily_totals=daily_totals
                    )

                if not isinstance(parsed, dict):
                    logger.error("Groq response JSON is not an object: %s", parsed)
                    call_usage.successful_calls = 0
                    call_usage.failed_calls = 1
                    aggregate_usage.add(call_usage)
                    daily_totals = self._record_call(
                        "non_object_json",
                        call_usage,
                        http_status=response.status_code,
                    )
                    return GroqChatResult(
                        content=None, usage=aggregate_usage, daily_totals=daily_totals
                    )

                aggregate_usage.add(call_usage)
                daily_totals = self._record_call(
                    "success", call_usage, http_status=response.status_code
                )
                return GroqChatResult(
                    content=parsed, usage=aggregate_usage, daily_totals=daily_totals
                )
            except httpx.HTTPStatusError as exc:
                body = exc.response.text.strip()
                call_usage = self._empty_usage()
                call_usage.attempts = 1
                call_usage.failed_calls = 1
                aggregate_usage.add(call_usage)
                daily_totals = self._record_call(
                    "http_error", call_usage, http_status=exc.response.status_code
                )
                logger.error(
                    "Groq API request failed (attempt %s/%s, status=%s, model=%s, strict_json_schema=%s): %s",
                    attempt,
                    self._config.groq_max_retries,
                    exc.response.status_code,
                    self._config.groq_model,
                    use_strict_json_schema,
                    body[:1000] or "<empty body>",
                )
                if use_strict_json_schema and self._should_fallback_to_json_object(
                    exc.response.status_code, body
                ):
                    logger.warning(
                        "Falling back to response_format=json_object for model %s after json_validate_failed.",
                        self._config.groq_model,
                    )
                    use_strict_json_schema = False
                if attempt >= self._config.groq_max_retries:
                    break
                time.sleep(backoff)
                backoff *= 2
            except httpx.RequestError:
                call_usage = self._empty_usage()
                call_usage.attempts = 1
                call_usage.failed_calls = 1
                aggregate_usage.add(call_usage)
                daily_totals = self._record_call("request_error", call_usage)
                logger.exception(
                    "Groq API request failed (attempt %s/%s, model=%s)",
                    attempt,
                    self._config.groq_max_retries,
                    self._config.groq_model,
                )
                if attempt >= self._config.groq_max_retries:
                    break
                time.sleep(backoff)
                backoff *= 2

        return GroqChatResult(
            content=None, usage=aggregate_usage, daily_totals=daily_totals
        )


__all__ = ["GroqClient"]
