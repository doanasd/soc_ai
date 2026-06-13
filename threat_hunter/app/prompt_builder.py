from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from .models import HuntDataset, HuntHypothesis

logger = logging.getLogger(__name__)

# ── OpenSearch Schema Description ────────────────────────────────────────────
# This tells the LLM exactly which fields are available in OpenSearch
# so it can compose valid queries.

OPENSEARCH_SCHEMA_DESCRIPTION = """
## OpenSearch Log Schema

The SOC logs are stored in OpenSearch with the following normalized schema.
Use these exact field names when constructing queries.

### Common Fields (all log types)
- `@timestamp` (date) — Event timestamp
- `log_type` (keyword) — One of: "waf", "vpc", "linux", "win"
- `vendor` (keyword) — One of: "aws", "Microsoft", "Linux"
- `action` (keyword) — Action taken (e.g. "block", "allow", "failed", "success")
- `outcome` (keyword) — "allowed", "blocked", "unknown"
- `asset_host` (keyword) — Hostname of the affected asset
- `message` (text) — Human-readable event description
- `correlation_id` (keyword) — Correlation identifier

### Network Fields
- `network.source_ip` (ip) — Source IP address
- `network.destination_ip` (ip) — Destination IP address
- `network.source_port` (integer) — Source port
- `network.destination_port` (integer) — Destination port
- `network.protocol` (keyword) — Protocol (tcp, udp, icmp)
- `network.method` (keyword) — HTTP method if applicable

### WAF-specific Fields (log_type: "waf")
- `waf.uri` (text) — Requested URI path
- `waf.host_header` (keyword) — Host header value
- `waf.rule_id` (keyword) — WAF rule that matched
- `waf.ja3` (keyword) — JA3 fingerprint
- `waf.ja4` (keyword) — JA4 fingerprint
- `waf.headers` (object) — HTTP request headers

### VPC Flow Fields (log_type: "vpc")
- `flow.packets` (long) — Packet count
- `flow.bytes` (long) — Byte count
- `flow.interface_id` (keyword) — Network interface ID

### Linux Fields (log_type: "linux")
- `linuxEvent.program` (keyword) — Program name (sshd, sudo, pam, ...)
- `linuxEvent.user` (keyword) — Username involved
- `linuxEvent.ruleID` (keyword) — Wazuh rule ID
- `linuxEvent.ruleGroups` (keyword) — Wazuh rule groups

### Windows Fields (log_type: "win")
- `winEvent.eventID` (keyword) — Windows Event ID
- `winEvent.logonType` (keyword) — Logon type
- `winEvent.process` (keyword) — Process name
- `winEvent.target_user` (keyword) — Target username

### Aggregation Fields (from dedup)
- `aggregation.count` (integer) — Number of raw events in this group
- `aggregation.first_seen` (float) — Unix timestamp of first event
- `aggregation.last_seen` (float) — Unix timestamp of last event
- `aggregation.rate_per_sec` (float) — Events per second in window
- `group_key` (keyword) — Dedup grouping key

### Enrichment Fields
- `maliciousIP.confidence_score` (integer) — AbuseIPDB confidence (0-100)
- `maliciousIP.source` (keyword) — Threat intel source
"""

# ── Query Syntax Guide ───────────────────────────────────────────────────────

QUERY_SYNTAX_GUIDE = """
## OpenSearch Query Syntax Guide

When constructing queries, use Lucene query syntax:

### Basic Queries
- Exact match: `field:"value"`
- Wildcard: `field:value*`
- Range: `field:[10 TO 100]`
- Boolean: `field1:"val1" AND field2:"val2"`
- NOT: `NOT field:"value"` or `field:!"value"`
- OR: `field:"val1" OR field:"val2"`

### IP Queries
- Exact IP: `network.source_ip:"1.2.3.4"`
- Subnet: `network.source_ip:"10.0.0.0/8"`

### Time Queries (use @timestamp)
- Relative: handled by the system's time_range parameter
- Absolute: `@timestamp:[2024-01-01 TO 2024-01-02]`

### Aggregation Note
- The system handles aggregations for you. Focus on constructing
  filter queries to narrow down specific events of interest.

### Examples
1. SSH brute force: `log_type:"linux" AND linuxEvent.program:"sshd" AND action:"failed"`
2. Blocked WAF: `log_type:"waf" AND action:"block" AND network.source_ip:"1.2.3.4"`
3. VPC traffic to DB: `log_type:"vpc" AND network.destination_port:"3306" AND action:"allow"`
4. High-rate events: `aggregation.rate_per_sec:[10 TO *]`
5. Specific host: `asset_host:"web-server-01"`
"""


def build_system_prompt() -> str:
    """Build the system prompt for the hunt analyzer agent."""
    return f"""You are an expert SOC Threat Hunter AI Agent. Your role is to proactively investigate 
security hypotheses by querying OpenSearch logs and analyzing the results.

{OPENSEARCH_SCHEMA_DESCRIPTION}

{QUERY_SYNTAX_GUIDE}

## Your Investigation Process

You follow a structured ReAct (Reason + Act) loop:

1. **THOUGHT**: Analyze the hypothesis and current evidence. What do you need to investigate?
2. **ACTION**: Specify an OpenSearch query to search for evidence. Format your action as:
   ```json
   {{"action": "search", "query": "<your Lucene query>", "reasoning": "<why this query>"}}
   ```
3. **OBSERVATION**: Review the returned log data.
4. **REPEAT** steps 1-3 if more evidence is needed (max 3 queries).
5. **CONCLUSION**: When ready, provide your final finding.

## Rules
- Be thorough but efficient. Each query should have a clear purpose.
- Start broad, then narrow down based on findings.
- Look for patterns: same IPs across different log types, time clustering, unusual ports.
- Consider both the volume AND the content of logs.
- Distinguish between internet noise and genuine threats.
- Do NOT fabricate evidence. Only reference data you've actually seen.
- For VPC flows, focus on destination_port, not source_port.
"""


def build_hypothesis_prompt(
    hypothesis: HuntHypothesis,
    dataset: HuntDataset,
    anomalies: List[Dict[str, Any]],
) -> str:
    """
    Build the user prompt for investigating a specific hypothesis.
    """
    # Format dataset overview
    overview_parts = [
        f"## Current Environment Overview (Last {dataset.lookback_hours}h)",
        f"- **Total Logs**: {dataset.total_logs:,}",
        f"- **Time Range**: {dataset.time_range_start} → {dataset.time_range_end}",
    ]

    if dataset.log_type_counts:
        type_str = ", ".join(f"{k}: {v:,}" for k, v in dataset.log_type_counts.items())
        overview_parts.append(f"- **Log Types**: {type_str}")

    if dataset.action_counts:
        action_str = ", ".join(f"{k}: {v:,}" for k, v in dataset.action_counts.items())
        overview_parts.append(f"- **Actions**: {action_str}")

    if dataset.top_source_ips:
        top_ips = ", ".join(
            f"{e.key} ({e.count:,})" for e in dataset.top_source_ips[:10]
        )
        overview_parts.append(f"- **Top Source IPs**: {top_ips}")

    if dataset.top_destination_ports:
        top_ports = ", ".join(
            f"port {e.key} ({e.count:,})" for e in dataset.top_destination_ports[:10]
        )
        overview_parts.append(f"- **Top Destination Ports**: {top_ports}")

    overview = "\n".join(overview_parts)

    # Format anomaly context
    anomaly_text = ""
    if anomalies:
        anomaly_lines = ["## Detected Anomalies"]
        for i, a in enumerate(anomalies, 1):
            anomaly_lines.append(
                f"{i}. [{a.get('severity', 'medium').upper()}] {a.get('description', 'N/A')}"
            )
        anomaly_text = "\n".join(anomaly_lines)

    # Build the prompt
    prompt = f"""## Threat Hunting Investigation

### Hypothesis to Investigate
- **ID**: {hypothesis.id}
- **Title**: {hypothesis.title}
- **Severity**: {hypothesis.severity.value}
- **Category**: {hypothesis.category}
- **Description**: {hypothesis.description}

### Suggested Starting Queries
{chr(10).join(f'- `{q}`' for q in hypothesis.suggested_queries)}

{overview}

{anomaly_text}

---

Begin your investigation. Use the THOUGHT → ACTION → OBSERVATION loop.
When you issue an ACTION, format it as a JSON object on a single line:
{{"action": "search", "query": "<your query>", "reasoning": "<why>"}}

When you have enough evidence, provide your CONCLUSION as a JSON object:
{{"action": "conclude", "verdict": "confirmed|suspicious|dismissed|inconclusive", "severity": "low|medium|high|critical", "confidence": 0-100, "title": "<finding title>", "summary": "<detailed summary>", "reasoning": "<step by step reasoning>", "evidence": ["<key evidence 1>", "..."], "recommended_actions": ["<action 1>", "..."]}}
"""

    return prompt


def build_observation_prompt(
    step_number: int,
    query_executed: str,
    results: List[Dict[str, Any]],
    result_count: int,
    max_display: int = 20,
) -> str:
    """
    Build the observation prompt after a tool call returns results.
    """
    # Truncate results for context window management
    display_results = results[:max_display]

    # Simplify each result to key fields
    simplified = []
    for r in display_results:
        source = r.get("_source", r)
        simplified.append(_simplify_log(source))

    results_json = json.dumps(simplified, indent=2, ensure_ascii=False, default=str)

    truncation_note = ""
    if result_count > max_display:
        truncation_note = f"\n(Showing {max_display} of {result_count} total results. Focus on patterns in the visible data.)"

    return f"""## OBSERVATION (Step {step_number})

**Query executed**: `{query_executed}`
**Results returned**: {result_count}{truncation_note}

```json
{results_json}
```

Continue your investigation. If you need more data, issue another ACTION.
If you have enough evidence, provide your CONCLUSION.
"""


def _simplify_log(log: Dict[str, Any]) -> Dict[str, Any]:
    """Extract the most relevant fields from a log entry for LLM consumption."""
    simplified: Dict[str, Any] = {}

    # Priority fields
    for field in [
        "log_type", "action", "outcome", "asset_host", "message",
        "@timestamp", "group_key",
    ]:
        if field in log:
            simplified[field] = log[field]

    # Network fields
    network = log.get("network", {})
    if isinstance(network, dict):
        for nf in ["source_ip", "destination_ip", "destination_port", "protocol", "method"]:
            if nf in network:
                simplified[f"net.{nf}"] = network[nf]

    # Aggregation
    agg = log.get("aggregation", {})
    if isinstance(agg, dict) and agg.get("count"):
        simplified["agg_count"] = agg["count"]
        if agg.get("rate_per_sec"):
            simplified["agg_rate"] = round(agg["rate_per_sec"], 2)

    # Type-specific fields
    for prefix in ["waf", "linuxEvent", "winEvent", "flow"]:
        sub = log.get(prefix, {})
        if isinstance(sub, dict):
            for k, v in sub.items():
                if v is not None and v != "":
                    simplified[f"{prefix}.{k}"] = v

    # Malicious IP enrichment
    mal = log.get("maliciousIP", {})
    if isinstance(mal, dict) and mal.get("confidence_score"):
        simplified["malicious_score"] = mal["confidence_score"]

    return simplified


__all__ = [
    "build_system_prompt",
    "build_hypothesis_prompt",
    "build_observation_prompt",
    "OPENSEARCH_SCHEMA_DESCRIPTION",
    "QUERY_SYNTAX_GUIDE",
]
