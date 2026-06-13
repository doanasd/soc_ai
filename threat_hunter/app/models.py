from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field  # type: ignore[import-not-found]


# ── Aggregation / Overview Data Models ───────────────────────────────────────

class TopEntry(BaseModel):
    """A single (key, count) entry used in top-N aggregation lists."""
    key: str
    count: int


class HourlyVolume(BaseModel):
    """Log volume for a specific hour bucket."""
    hour: str  # ISO format or HH:MM
    count: int


class HuntDataset(BaseModel):
    """
    Lightweight overview data collected from OpenSearch aggregations.
    Replaces the old in-memory JSON loading approach.
    """
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    lookback_hours: int = 24
    time_range_start: Optional[str] = None
    time_range_end: Optional[str] = None

    # Total counts by log type
    total_logs: int = 0
    log_type_counts: Dict[str, int] = Field(default_factory=dict)  # e.g. {"waf": 5000, "vpc": 12000, "linux": 300}

    # Action distribution
    action_counts: Dict[str, int] = Field(default_factory=dict)  # e.g. {"block": 8000, "allow": 4000}

    # Top-N aggregations
    top_source_ips: List[TopEntry] = Field(default_factory=list)
    top_destination_ips: List[TopEntry] = Field(default_factory=list)
    top_destination_ports: List[TopEntry] = Field(default_factory=list)

    # Volume over time
    hourly_volume: List[HourlyVolume] = Field(default_factory=list)

    # Extra context
    unique_source_ips: int = 0
    unique_destination_ips: int = 0


# ── Hypothesis Models ────────────────────────────────────────────────────────

class HypothesisSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class HuntHypothesis(BaseModel):
    """
    A threat hunting hypothesis generated from anomaly analysis.
    Example: "Brute-force detected — port 22 volume increased 300% vs baseline"
    """
    id: str  # e.g. "hyp_brute_force_ssh_001"
    title: str
    description: str
    severity: HypothesisSeverity = HypothesisSeverity.MEDIUM
    category: str  # e.g. "brute_force", "port_scan", "data_exfiltration"
    suggested_queries: List[str] = Field(default_factory=list)
    anomaly_details: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ── Finding / Conclusion Models ──────────────────────────────────────────────

class FindingVerdict(str, Enum):
    CONFIRMED = "confirmed"
    SUSPICIOUS = "suspicious"
    DISMISSED = "dismissed"
    INCONCLUSIVE = "inconclusive"


class HuntFinding(BaseModel):
    """
    Final conclusion after the AI agent investigates a hypothesis.
    Stored as JSONL and optionally sent via Telegram.
    """
    id: str  # e.g. "finding_001"
    hypothesis_id: str
    hypothesis_title: str
    verdict: FindingVerdict
    severity: HypothesisSeverity
    confidence: int = Field(ge=0, le=100, default=50)

    title: str
    summary: str
    reasoning: str
    evidence: List[str] = Field(default_factory=list)  # Key log excerpts
    recommended_actions: List[str] = Field(default_factory=list)

    # Agent metadata
    tool_calls_made: int = 0
    queries_executed: List[str] = Field(default_factory=list)

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    hunt_session_id: str = ""

    def to_output_dict(self) -> Dict[str, Any]:
        """Serialize to a dict suitable for JSONL output."""
        return self.model_dump(mode="json")


# ── Baseline Models ──────────────────────────────────────────────────────────

class BaselineMetrics(BaseModel):
    """Rolling baseline metrics computed over multiple hunt sessions."""
    computed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    days_of_data: int = 7

    avg_total_logs: float = 0.0
    avg_log_type_counts: Dict[str, float] = Field(default_factory=dict)
    avg_action_counts: Dict[str, float] = Field(default_factory=dict)
    avg_top_source_ip_volume: float = 0.0

    # Historical datasets used for baseline computation
    history: List[Dict[str, Any]] = Field(default_factory=list)


# ── Agent Tool Call Models ───────────────────────────────────────────────────

class AgentToolCall(BaseModel):
    """Represents a tool call the LLM wants to execute."""
    tool_name: str  # "search_logs"
    query: str  # OpenSearch query string
    index: Optional[str] = None
    size: int = 50
    reasoning: str = ""  # Why the agent wants to run this query


class AgentStep(BaseModel):
    """A single step in the ReAct loop."""
    step_number: int
    thought: str
    action: Optional[AgentToolCall] = None
    observation: Optional[str] = None  # Summarized results from the tool


# ── Hunt Session Model ───────────────────────────────────────────────────────

class HuntSession(BaseModel):
    """Tracks the overall hunt session."""
    session_id: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    lookback_hours: int = 24

    dataset: Optional[HuntDataset] = None
    hypotheses: List[HuntHypothesis] = Field(default_factory=list)
    findings: List[HuntFinding] = Field(default_factory=list)
    status: str = "running"  # running, completed, failed


__all__ = [
    "TopEntry",
    "HourlyVolume",
    "HuntDataset",
    "HypothesisSeverity",
    "HuntHypothesis",
    "FindingVerdict",
    "HuntFinding",
    "BaselineMetrics",
    "AgentToolCall",
    "AgentStep",
    "HuntSession",
]
