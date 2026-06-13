from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import (  # type: ignore[import-not-found]
    BaseModel,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)


class Event(BaseModel):
    """Normalized input event from the JSON log stream."""

    timestamp: Optional[datetime] = None
    log_type: Optional[str] = None
    source: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    uri: Optional[str] = None
    method: Optional[str] = None
    action: Optional[str] = None
    rule_id: Optional[str] = None
    message: Optional[str] = None
    headers: Optional[Dict[str, Any]] = None
    country: Optional[str] = None
    user_agent: Optional[str] = None
    labels: Optional[List[str]] = None
    raw: Optional[str] = None

    # Allow arbitrary extra fields to future‑proof the schema
    model_config = {"extra": "allow"}

    @model_validator(mode="before")
    @classmethod
    def normalize_nested_fields(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value

        data = dict(value)
        sample_event = data.get("sample_event")
        if not isinstance(sample_event, dict):
            return data

        network = sample_event.get("network")
        if not isinstance(network, dict):
            network = {}

        if data.get("timestamp") is None:
            raw_time = sample_event.get("time")
            if raw_time is not None:
                try:
                    epoch_seconds = float(str(raw_time)) / 1000.0
                    data["timestamp"] = datetime.fromtimestamp(
                        epoch_seconds, tz=timezone.utc
                    )
                except (TypeError, ValueError, OverflowError):
                    pass

        data.setdefault("log_type", sample_event.get("log_type"))
        data.setdefault("source", sample_event.get("vendor"))
        data.setdefault("src_ip", network.get("source_ip"))
        data.setdefault("dst_ip", network.get("destination_ip"))
        data.setdefault("action", sample_event.get("action") or sample_event.get("outcome"))
        data.setdefault("country", network.get("country"))
        data.setdefault("message", sample_event.get("message"))

        return data


class ModelAnalysis(BaseModel):
    """Structured analysis returned by the LLM."""

    should_alert: bool
    severity: str
    confidence: int = Field(ge=0, le=100)
    category: str
    title: str
    summary: str
    reasoning: str
    recommended_actions: List[str]
    dedup_key: str

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = {"low", "medium", "high", "critical"}
        value = v.lower()
        if value not in allowed:
            # Default to low for unknown / malformed values
            return "low"
        return value

    @field_validator("confidence", mode="before")
    @classmethod
    def normalize_confidence(cls, v: Any) -> int:
        try:
            ivalue = int(v)
        except Exception:
            return 50
        return max(0, min(100, ivalue))


class Alert(BaseModel):
    """Alert emitted by the service."""

    event: Dict[str, Any]
    analysis: ModelAnalysis
    usage: Optional[Dict[str, Any]] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class GroqMessage(BaseModel):
    role: str
    content: str


class GroqRequest(BaseModel):
    model: str
    messages: List[GroqMessage]
    temperature: float = 0.0
    max_completion_tokens: int = 512
    reasoning_effort: Optional[str] = None
    include_reasoning: Optional[bool] = None
    response_format: Dict[str, Any] = Field(
        default_factory=lambda: {"type": "json_object"}
    )


class GroqChoiceMessage(BaseModel):
    role: str
    content: str


class GroqChoice(BaseModel):
    index: int
    message: GroqChoiceMessage


class GroqUsagePromptDetails(BaseModel):
    cached_tokens: int = 0


class GroqUsage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    prompt_tokens_details: Optional[GroqUsagePromptDetails] = None


class GroqResponse(BaseModel):
    choices: List[GroqChoice]
    usage: Optional[GroqUsage] = None


class ModelUsage(BaseModel):
    model: str
    attempts: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    prompt_tokens: int = 0
    cached_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    input_cost_usd: float = 0.0
    cached_input_cost_usd: float = 0.0
    output_cost_usd: float = 0.0
    total_cost_usd: float = 0.0

    def add(self, other: "ModelUsage") -> "ModelUsage":
        self.attempts += other.attempts
        self.successful_calls += other.successful_calls
        self.failed_calls += other.failed_calls
        self.prompt_tokens += other.prompt_tokens
        self.cached_tokens += other.cached_tokens
        self.completion_tokens += other.completion_tokens
        self.total_tokens += other.total_tokens
        self.input_cost_usd += other.input_cost_usd
        self.cached_input_cost_usd += other.cached_input_cost_usd
        self.output_cost_usd += other.output_cost_usd
        self.total_cost_usd += other.total_cost_usd
        return self


class GroqChatResult(BaseModel):
    content: Optional[Dict[str, Any]] = None
    usage: ModelUsage
    daily_totals: Dict[str, Any] = Field(default_factory=dict)


class BatchAnalysisResult(BaseModel):
    outcome: str = "no_alert"
    alert: Optional[Alert] = None
    analysis: Optional[ModelAnalysis] = None
    usage: ModelUsage
    daily_totals: Dict[str, Any] = Field(default_factory=dict)


MODEL_ANALYSIS_JSON_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "should_alert": {"type": "boolean"},
        "severity": {
            "type": "string",
            "enum": ["low", "medium", "high", "critical"],
        },
        "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
        "category": {"type": "string"},
        "title": {"type": "string"},
        "summary": {"type": "string"},
        "reasoning": {"type": "string"},
        "recommended_actions": {
            "type": "array",
            "items": {"type": "string"},
        },
        "dedup_key": {"type": "string"},
    },
    "required": [
        "should_alert",
        "severity",
        "confidence",
        "category",
        "title",
        "summary",
        "reasoning",
        "recommended_actions",
        "dedup_key",
    ],
    "additionalProperties": False,
}


def parse_model_analysis(raw: Any) -> ModelAnalysis:
    """Parse and sanitize raw model output into a ModelAnalysis instance."""

    if isinstance(raw, str):
        import json

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValidationError.from_exception_data(
                "ModelAnalysis", [{"type": "value_error.jsondecode", "loc": ("__root__",), "msg": str(exc), "input": raw}]  # type: ignore[arg-type]
            )
    elif isinstance(raw, dict):
        data = raw
    else:
        raise ValidationError.from_exception_data(
            "ModelAnalysis",
            [
                {
                    "type": "type_error",
                    "loc": ("__root__",),
                    "msg": f"Unsupported type for model output: {type(raw)}",
                    "input": raw,
                }
            ],
        )

    # Basic sanitization / defaults for required keys
    data.setdefault("should_alert", False)
    data.setdefault("severity", "low")
    data.setdefault("confidence", 50)
    data.setdefault("category", "uncategorized")
    data.setdefault("title", "Unspecified alert")
    data.setdefault("summary", "")
    data.setdefault("reasoning", "")
    data.setdefault("recommended_actions", [])
    data.setdefault("dedup_key", "")

    return ModelAnalysis.model_validate(data)


__all__ = [
    "Event",
    "ModelAnalysis",
    "Alert",
    "GroqMessage",
    "GroqRequest",
    "GroqResponse",
    "GroqChatResult",
    "GroqUsage",
    "ModelUsage",
    "BatchAnalysisResult",
    "MODEL_ANALYSIS_JSON_SCHEMA",
    "parse_model_analysis",
]
