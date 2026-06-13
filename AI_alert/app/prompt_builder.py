from __future__ import annotations

import json
from typing import Any, Dict, List

from .models import Event, GroqMessage

SYSTEM_PROMPT = """
You are an experienced Security Operations Center (SOC) analyst specializing in alert triage.

Your task is to decide whether a single normalized security event warrants a structured alert for human analysts.

Rules:
- Respond with a single JSON object only. No prose, no markdown, no code fences.
- Do NOT invent or hallucinate fields or evidence that are not present in the event or provided context.
- If information is missing, explicitly reflect that in your reasoning.
- Treat commodity internet background noise, generic scans, and obviously blocked WAF noise as low severity or non-alerts unless there is strong evidence of operational impact.
- Prefer fewer, high-quality alerts over noisy or speculative alerts.
- For VPC Flow logs, prioritize destination port/exposure over source port. Do NOT infer a server role or compromise from source port alone.
- A single low-volume internal-to-internal accepted flow to a non-sensitive destination port is usually not alert-worthy without corroborating indicators.
- For VPC or non-HTTP network alerts, recommend network and host controls such as security groups, NACLs, host firewall, and service logs. Do NOT recommend WAF unless the traffic is HTTP/S and the event is clearly WAF-related.

Output JSON schema:
- should_alert: boolean
- severity: one of ["low", "medium", "high", "critical"]
- confidence: integer from 0 to 100
- category: short string category (e.g. "web_attack", "brute_force", "reconnaissance")
- title: concise human-readable title
- summary: 1-3 sentence summary for analysts
- reasoning: brief explanation of why you chose this outcome
- recommended_actions: array of concrete next steps for analysts
- dedup_key: string used to deduplicate alerts for similar events

If the event clearly does not warrant an alert, set should_alert=false and choose a low severity and low confidence.
"""

WINDOW_SYSTEM_PROMPT = """
You are an experienced Security Operations Center (SOC) analyst specializing in time-window triage.

Your task is to review a summarized window of security activity and decide whether the overall period warrants a single structured alert for human analysts.

Rules:
- Respond with a single JSON object only. No prose, no markdown, no code fences.
- Do NOT invent or hallucinate fields or evidence that are not present in the window summary or provided context.
- Prefer at most one high-signal alert for the most important issue in the window.
- If the window mostly contains benign or routine traffic, set should_alert=false.
- Focus on business-impacting behavior, exposed management or data-store services, repeated suspicious patterns, or clear signs of new exposure.
- If `historical_correlation` is present, use it to judge whether the current window is isolated, recurring, or sustained across the last hour.
- For VPC Flow logs, prioritize destination port and exposure. Do NOT infer suspiciousness from source port alone.
- A single low-volume internal-to-internal accepted flow to a non-sensitive destination port is usually not alert-worthy without corroborating indicators.
- For VPC or non-HTTP network alerts, recommend network and host controls such as security groups, NACLs, host firewall, and service logs. Do NOT recommend WAF unless the traffic is HTTP/S and the activity is clearly WAF-related.
- For blocked WAF anomalies, a single isolated matching window in the last hour should usually stay low severity or no-alert unless service impact or extreme volume is explicit.
- Repeated matching WAF anomalies across multiple windows may justify medium severity.
- High severity for WAF flood or DDoS-style behavior should usually require sustained multi-window recurrence in the last hour or explicit service degradation evidence.
- Use `possible_ddos` only when recurrence is clearly multi-window and the evidence shows broad or sustained pressure, not for a one-off blocked spike.
- Reserve `critical` for confirmed material service impact, not just repeated blocked traffic.

Output JSON schema:
- should_alert: boolean
- severity: one of ["low", "medium", "high", "critical"]
- confidence: integer from 0 to 100
- category: short string category
- title: concise human-readable title
- summary: 1-3 sentence summary for analysts
- reasoning: brief explanation of why you chose this outcome
- recommended_actions: array of concrete next steps for analysts
- dedup_key: string used to deduplicate recurring windows with the same underlying concern
"""

STATUS_SYSTEM_PROMPT = """
You are an experienced Security Operations Center (SOC) analyst specializing in security monitoring health and interval triage.

Your task is to review a summarized reporting interval and decide whether the interval warrants a structured alert for human analysts.

Rules:
- Respond with a single JSON object only. No prose, no markdown, no code fences.
- Do NOT invent or hallucinate fields or evidence that are not present in the interval summary or provided context.
- Distinguish between:
  - normal interval with no important alerts
  - telemetry or visibility gap
  - suspicious activity that still merits escalation
- Missing or materially degraded required telemetry can be alert-worthy even when no direct attack evidence is present.
- If telemetry and activity look healthy and there are no important issues, set should_alert=false.
- Use category `telemetry_gap` for missing or materially degraded required monitoring data.

Output JSON schema:
- should_alert: boolean
- severity: one of ["low", "medium", "high", "critical"]
- confidence: integer from 0 to 100
- category: short string category
- title: concise human-readable title
- summary: 1-3 sentence summary for analysts
- reasoning: brief explanation of why you chose this outcome
- recommended_actions: array of concrete next steps for analysts
- dedup_key: string used to deduplicate recurring interval issues
"""


def is_gpt_oss_model(model_name: str | None) -> bool:
    if not model_name:
        return False
    return model_name.strip().lower().startswith("openai/gpt-oss-")


def build_messages(
    event: Event, context_markdown: str, model_name: str | None = None
) -> List[GroqMessage]:
    """Build chat messages for the Groq LLM."""

    event_json = json.dumps(event.model_dump(mode="json"), ensure_ascii=False, indent=2)

    user_content = SYSTEM_PROMPT.strip() + "\n\n"
    user_content += (
        "You will receive:\n"
        "1) Analyst and environment context\n"
        "2) A single normalized security event as JSON\n\n"
        "Return exactly one JSON object that matches the required fields.\n"
        "Do not wrap the JSON in markdown or add any extra text.\n\n"
        "=== ANALYST CONTEXT (markdown, may be truncated) ===\n"
        f"{context_markdown}\n\n"
        "=== EVENT JSON ===\n"
        f"{event_json}\n"
    )

    if is_gpt_oss_model(model_name):
        return [GroqMessage(role="user", content=user_content)]

    return [
        GroqMessage(role="system", content=SYSTEM_PROMPT.strip()),
        GroqMessage(
            role="user",
            content=user_content.replace(SYSTEM_PROMPT.strip() + "\n\n", "", 1),
        ),
    ]


def build_window_messages(
    window_summary: Dict[str, Any],
    context_markdown: str,
    model_name: str | None = None,
) -> List[GroqMessage]:
    summary_json = json.dumps(window_summary, ensure_ascii=False, indent=2)

    user_content = WINDOW_SYSTEM_PROMPT.strip() + "\n\n"
    user_content += (
        "You will receive:\n"
        "1) Analyst and environment context\n"
        "2) A summarized time window of security activity as JSON\n\n"
        "Assess the entire window and return exactly one JSON object.\n"
        "If nothing in the window is worth escalating, set should_alert=false.\n\n"
        "=== ANALYST CONTEXT (markdown, may be truncated) ===\n"
        f"{context_markdown}\n\n"
        "=== WINDOW SUMMARY JSON ===\n"
        f"{summary_json}\n\n"
        "If `historical_correlation` is present, use it explicitly in the reasoning and severity choice.\n"
    )

    if is_gpt_oss_model(model_name):
        return [GroqMessage(role="user", content=user_content)]

    return [
        GroqMessage(role="system", content=WINDOW_SYSTEM_PROMPT.strip()),
        GroqMessage(
            role="user",
            content=user_content.replace(WINDOW_SYSTEM_PROMPT.strip() + "\n\n", "", 1),
        ),
    ]


def build_status_messages(
    interval_summary: Dict[str, Any],
    context_markdown: str,
    model_name: str | None = None,
) -> List[GroqMessage]:
    summary_json = json.dumps(interval_summary, ensure_ascii=False, indent=2)

    user_content = STATUS_SYSTEM_PROMPT.strip() + "\n\n"
    user_content += (
        "You will receive:\n"
        "1) Analyst and environment context\n"
        "2) A summarized reporting interval as JSON\n\n"
        "Decide whether the interval is operationally normal or whether it warrants an alert.\n"
        "If no important issue exists, set should_alert=false.\n\n"
        "=== ANALYST CONTEXT (markdown, may be truncated) ===\n"
        f"{context_markdown}\n\n"
        "=== INTERVAL SUMMARY JSON ===\n"
        f"{summary_json}\n"
    )

    if is_gpt_oss_model(model_name):
        return [GroqMessage(role="user", content=user_content)]

    return [
        GroqMessage(role="system", content=STATUS_SYSTEM_PROMPT.strip()),
        GroqMessage(
            role="user",
            content=user_content.replace(STATUS_SYSTEM_PROMPT.strip() + "\n\n", "", 1),
        ),
    ]


__all__ = [
    "build_messages",
    "build_status_messages",
    "build_window_messages",
    "STATUS_SYSTEM_PROMPT",
    "SYSTEM_PROMPT",
    "WINDOW_SYSTEM_PROMPT",
    "is_gpt_oss_model",
]
