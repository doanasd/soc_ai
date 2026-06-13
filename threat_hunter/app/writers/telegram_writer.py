from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx  # type: ignore[import-not-found]

from ..config import HuntConfig
from ..models import HuntFinding, HuntSession

logger = logging.getLogger(__name__)


def _severity_emoji(severity: str) -> str:
    return {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
    }.get(severity, "⚪")


def _verdict_emoji(verdict: str) -> str:
    return {
        "confirmed": "🚨",
        "suspicious": "⚠️",
        "dismissed": "✅",
        "inconclusive": "❓",
    }.get(verdict, "❓")


def format_finding_message(finding: HuntFinding) -> str:
    """Format a HuntFinding for Telegram notification."""
    sev = _severity_emoji(finding.severity.value)
    ver = _verdict_emoji(finding.verdict.value)

    lines = [
        f"{ver} THREAT HUNT FINDING {sev}",
        f"━━━━━━━━━━━━━━━━━━━━━━━━",
        f"📋 {finding.title}",
        f"",
        f"🎯 Verdict: {finding.verdict.value.upper()}",
        f"⚡ Severity: {finding.severity.value.upper()}",
        f"📊 Confidence: {finding.confidence}%",
        f"",
        f"🔍 Hypothesis: {finding.hypothesis_title}",
    ]

    if finding.summary:
        # Truncate summary for Telegram message limits
        summary = finding.summary[:500]
        if len(finding.summary) > 500:
            summary += "..."
        lines.extend(["", f"📝 Summary:", summary])

    if finding.evidence:
        lines.extend(["", "🔬 Key Evidence:"])
        for i, ev in enumerate(finding.evidence[:5], 1):
            evidence_text = ev[:150]
            if len(ev) > 150:
                evidence_text += "..."
            lines.append(f"  {i}. {evidence_text}")

    if finding.recommended_actions:
        lines.extend(["", "🛡️ Recommended Actions:"])
        for action in finding.recommended_actions[:4]:
            lines.append(f"  • {action}")

    lines.extend([
        "",
        f"🔧 Queries executed: {finding.tool_calls_made}",
        f"🆔 Finding: {finding.id}",
    ])

    return "\n".join(lines)


def format_session_summary(session: HuntSession) -> str:
    """Format a hunt session summary for Telegram."""
    total = len(session.findings)
    confirmed = sum(1 for f in session.findings if f.verdict.value == "confirmed")
    suspicious = sum(1 for f in session.findings if f.verdict.value == "suspicious")
    dismissed = sum(1 for f in session.findings if f.verdict.value == "dismissed")
    inconclusive = sum(1 for f in session.findings if f.verdict.value == "inconclusive")

    lines = [
        "🏹 THREAT HUNT SESSION COMPLETE",
        f"━━━━━━━━━━━━━━━━━━━━━━━━",
        f"🆔 Session: {session.session_id}",
        f"⏰ Started: {session.started_at.strftime('%Y-%m-%d %H:%M UTC')}",
        f"📅 Lookback: {session.lookback_hours}h",
        f"",
        f"📊 Results:",
        f"  • Total findings: {total}",
        f"  🚨 Confirmed: {confirmed}",
        f"  ⚠️  Suspicious: {suspicious}",
        f"  ✅ Dismissed: {dismissed}",
        f"  ❓ Inconclusive: {inconclusive}",
    ]

    if session.dataset:
        lines.extend([
            f"",
            f"📈 Environment Overview:",
            f"  • Total logs analyzed: {session.dataset.total_logs:,}",
            f"  • Log types: {', '.join(f'{k}={v:,}' for k, v in session.dataset.log_type_counts.items())}",
            f"  • Hypotheses investigated: {len(session.hypotheses)}",
        ])

    # Highlight critical/high findings
    important_findings = [
        f for f in session.findings
        if f.verdict.value in ("confirmed", "suspicious")
        and f.severity.value in ("high", "critical")
    ]
    if important_findings:
        lines.extend(["", "⚡ Critical/High Findings:"])
        for f in important_findings[:5]:
            lines.append(
                f"  {_severity_emoji(f.severity.value)} [{f.verdict.value.upper()}] {f.title}"
            )

    return "\n".join(lines)


class TelegramNotifier:
    """Sends threat hunting findings and session summaries via Telegram."""

    def __init__(self, config: HuntConfig) -> None:
        self._bot_token = config.telegram_bot_token
        self._chat_id = config.telegram_chat_id
        self._enabled = bool(self._bot_token and self._chat_id)
        self._client: Optional[httpx.Client] = None

        if self._enabled:
            self._client = httpx.Client(
                base_url=f"https://api.telegram.org/bot{self._bot_token}",
                timeout=config.telegram_timeout_seconds,
            )

    @property
    def enabled(self) -> bool:
        return self._enabled

    def send_finding(self, finding: HuntFinding) -> None:
        """Send a finding notification."""
        if not self._enabled:
            return

        # Only send confirmed or suspicious findings to avoid noise
        if finding.verdict.value in ("dismissed", "inconclusive"):
            logger.debug(
                "Skipping Telegram for %s finding: %s",
                finding.verdict.value, finding.id,
            )
            return

        self._send_text(
            format_finding_message(finding),
            error_prefix="Failed to send Telegram finding.",
        )

    def send_session_summary(self, session: HuntSession) -> None:
        """Send session completion summary."""
        if not self._enabled:
            return

        self._send_text(
            format_session_summary(session),
            error_prefix="Failed to send Telegram session summary.",
        )

    def _send_text(self, text: str, error_prefix: str) -> None:
        if not self._enabled or self._client is None:
            return

        # Telegram has a 4096 char limit
        if len(text) > 4000:
            text = text[:3997] + "..."

        payload = {
            "chat_id": self._chat_id,
            "text": text,
            "disable_web_page_preview": True,
        }

        try:
            response = self._client.post("/sendMessage", json=payload)
            response.raise_for_status()
            data = response.json()
            if not data.get("ok", False):
                logger.error("Telegram sendMessage failed: %s", data)
        except Exception:
            logger.exception(error_prefix)

    def close(self) -> None:
        if self._client is not None:
            self._client.close()


__all__ = [
    "TelegramNotifier",
    "format_finding_message",
    "format_session_summary",
]
