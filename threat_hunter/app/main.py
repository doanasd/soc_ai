from __future__ import annotations

import logging
import signal
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from .config import HuntConfig, load_config
from .mcp_client import MCPClient
from .data_collector import DataCollector
from .baseline_tracker import BaselineTracker
from .hypothesis_engine import HypothesisEngine
from .hunt_analyzer import HuntAnalyzer
from .investigation_queue_reader import InvestigationQueueReader
from .models import HuntSession, HuntFinding, HuntHypothesis
from .writers.jsonl_writer import append_finding
from .writers.telegram_writer import TelegramNotifier

logger = logging.getLogger(__name__)

# ── Graceful shutdown ────────────────────────────────────────────────────────
_shutdown_requested = False


def _handle_signal(signum: int, frame: Any) -> None:
    global _shutdown_requested
    logger.info("Received signal %d — requesting graceful shutdown.", signum)
    _shutdown_requested = True


def setup_logging(level: int) -> None:
    """Configure structured logging."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


# ── Alert-triggered investigation ────────────────────────────────────────────

def run_alert_investigation(
    config: HuntConfig,
    alert_requests: List[Dict[str, Any]],
    mcp_client: MCPClient,
    data_collector: DataCollector,
    hypothesis_engine: HypothesisEngine,
    hunt_analyzer: HuntAnalyzer,
    telegram: TelegramNotifier,
) -> List[HuntFinding]:
    """
    Investigate alert(s) from AI Alert immediately via MCP.

    This is the NEW event-driven flow:
    AI Alert detects → writes queue → Threat Hunter picks up → MCP investigates
    """
    session_id = f"alert_hunt_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    findings: List[HuntFinding] = []

    logger.info("=" * 70)
    logger.info(
        "⚡ ALERT-TRIGGERED INVESTIGATION: %s (%d alert(s))",
        session_id, len(alert_requests),
    )
    logger.info("=" * 70)

    # Collect a lightweight dataset for context (may be empty if MCP is down)
    try:
        dataset = data_collector.collect()
    except Exception:
        logger.warning("Could not collect overview data. Proceeding with minimal context.")
        from .models import HuntDataset
        dataset = HuntDataset()

    for i, request in enumerate(alert_requests, 1):
        if _shutdown_requested:
            logger.info("Shutdown requested — stopping alert investigations.")
            break

        # Convert alert to hypothesis
        hypothesis = hypothesis_engine.from_alert_request(request)

        logger.info(
            "\n── [%d/%d] Investigating: %s ──",
            i, len(alert_requests), hypothesis.title,
        )
        logger.info(
            "   Severity: %s | Category: %s | Confidence: %d%%",
            request.get("alert_severity", "?").upper(),
            request.get("alert_category", "?"),
            request.get("alert_confidence", 0),
        )

        # Run the AI agent investigation via MCP
        finding = hunt_analyzer.investigate(
            hypothesis=hypothesis,
            dataset=dataset,
            anomalies=[],  # Anomalies already analyzed by AI Alert
            session_id=session_id,
        )
        findings.append(finding)

        # Log verdict
        verdict_icon = {
            "confirmed": "🚨",
            "suspicious": "⚠️",
            "dismissed": "✅",
            "inconclusive": "❓",
        }.get(finding.verdict.value, "❓")

        logger.info(
            "   %s Verdict: %s | Severity: %s | Confidence: %d%%",
            verdict_icon,
            finding.verdict.value.upper(),
            finding.severity.value.upper(),
            finding.confidence,
        )

        # Write finding
        append_finding(config.findings_output_path, finding)
        telegram.send_finding(finding)

    logger.info(
        "⚡ Alert investigation complete: %d finding(s) from %d alert(s)",
        len(findings), len(alert_requests),
    )

    return findings


# ── Scheduled hunt session (existing logic) ──────────────────────────────────

def run_hunt_session(
    config: HuntConfig,
    mcp_client: MCPClient,
    data_collector: DataCollector,
    baseline_tracker: BaselineTracker,
    hypothesis_engine: HypothesisEngine,
    hunt_analyzer: HuntAnalyzer,
    telegram: TelegramNotifier,
) -> HuntSession:
    """
    Execute a single scheduled threat hunting session:
    1. Collect overview data from OpenSearch
    2. Compare against baseline to detect anomalies
    3. Generate hypotheses
    4. Investigate each hypothesis via AI agent
    5. Output findings
    """
    session_id = f"hunt_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    session = HuntSession(session_id=session_id, lookback_hours=config.hunt_lookback_hours)

    logger.info("=" * 70)
    logger.info("🏹 SCHEDULED THREAT HUNT SESSION STARTED: %s", session_id)
    logger.info("   Lookback: %dh | Interval: %ds", config.hunt_lookback_hours, config.hunt_interval_seconds)
    logger.info("=" * 70)

    try:
        # ── Step 1: Collect overview data ────────────────────────────────────
        logger.info("📊 Step 1/5: Collecting environment overview...")
        dataset = data_collector.collect()
        session.dataset = dataset

        if dataset.total_logs == 0:
            logger.warning("⚠️  No logs found in the last %dh. Skipping investigation.", config.hunt_lookback_hours)
            session.status = "completed"
            session.completed_at = datetime.now(timezone.utc)
            return session

        logger.info(
            "   Total logs: %s | Types: %s | Unique src IPs: %d",
            f"{dataset.total_logs:,}",
            dataset.log_type_counts,
            dataset.unique_source_ips,
        )

        # ── Step 2: Detect anomalies ─────────────────────────────────────────
        logger.info("🔎 Step 2/5: Detecting anomalies against baseline...")
        anomalies = baseline_tracker.detect_anomalies(dataset)

        if anomalies:
            for a in anomalies:
                logger.info(
                    "   [%s] %s", a.get("severity", "?").upper(), a.get("description", ""),
                )
        else:
            logger.info("   No anomalies detected (baseline may need more history).")

        # ── Step 3: Generate hypotheses ──────────────────────────────────────
        logger.info("💡 Step 3/5: Generating hunting hypotheses...")
        hypotheses = hypothesis_engine.generate_hypotheses(dataset, anomalies)
        session.hypotheses = hypotheses

        logger.info("   Generated %d hypotheses:", len(hypotheses))
        for h in hypotheses:
            logger.info("   • [%s] %s", h.severity.value.upper(), h.title)

        # ── Step 4: Investigate each hypothesis ──────────────────────────────
        logger.info("🔍 Step 4/5: Investigating hypotheses via AI agent...")
        findings: List[HuntFinding] = []

        for i, hypothesis in enumerate(hypotheses, 1):
            if _shutdown_requested:
                logger.info("Shutdown requested — stopping investigations.")
                break

            logger.info(
                "\n── Investigating %d/%d: %s ──", i, len(hypotheses), hypothesis.title,
            )

            finding = hunt_analyzer.investigate(
                hypothesis=hypothesis,
                dataset=dataset,
                anomalies=anomalies,
                session_id=session_id,
            )
            findings.append(finding)

            # Log verdict
            verdict_icon = {
                "confirmed": "🚨",
                "suspicious": "⚠️",
                "dismissed": "✅",
                "inconclusive": "❓",
            }.get(finding.verdict.value, "❓")

            logger.info(
                "   %s Verdict: %s | Severity: %s | Confidence: %d%%",
                verdict_icon,
                finding.verdict.value.upper(),
                finding.severity.value.upper(),
                finding.confidence,
            )

        session.findings = findings

        # ── Step 5: Output findings ──────────────────────────────────────────
        logger.info("📝 Step 5/5: Writing findings...")

        for finding in findings:
            # Write to JSONL
            append_finding(config.findings_output_path, finding)

            # Send to Telegram (only confirmed/suspicious)
            telegram.send_finding(finding)

        # Update baseline with current data
        baseline_tracker.update_baseline(dataset)

        # Send session summary
        session.status = "completed"
        session.completed_at = datetime.now(timezone.utc)
        telegram.send_session_summary(session)

        # Final summary
        confirmed = sum(1 for f in findings if f.verdict.value == "confirmed")
        suspicious = sum(1 for f in findings if f.verdict.value == "suspicious")

        logger.info("\n" + "=" * 70)
        logger.info("🏹 SESSION COMPLETE: %s", session_id)
        logger.info(
            "   Findings: %d total | %d confirmed | %d suspicious",
            len(findings), confirmed, suspicious,
        )
        logger.info(
            "   Output: %s", config.findings_output_path,
        )
        logger.info("=" * 70)

    except Exception:
        logger.exception("Hunt session failed")
        session.status = "failed"
        session.completed_at = datetime.now(timezone.utc)

    return session


# ── Main entry point ─────────────────────────────────────────────────────────

def main() -> None:
    """
    Main entry point — runs a dual-mode loop:

    1. EVENT-DRIVEN: Watches the investigation queue for alerts from AI Alert.
       When a new alert arrives, immediately triggers an MCP-based investigation.

    2. SCHEDULED: Every 6 hours, runs a full proactive hunting session
       (baseline comparison → hypothesis generation → investigation).

    This ensures:
    - No detection delay: AI Alert triggers are investigated in seconds.
    - No blind spots: Scheduled hunts catch low-and-slow attacks.
    """
    config = load_config()
    setup_logging(config.log_level)

    logger.info("🏹 Threat Hunter starting up (dual-mode)...")
    logger.info("   MCP Server: %s", config.mcp_server_url)
    logger.info("   LLM Model: %s", config.groq_model)
    logger.info("   Scheduled hunt: every %ds (%dh lookback)",
                config.hunt_interval_seconds, config.hunt_lookback_hours)
    logger.info("   Investigation queue: %s (poll every %.0fs)",
                config.investigation_queue_path, config.investigation_queue_poll_seconds)
    logger.info("   Output: %s", config.findings_output_path)

    # Register signal handlers
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    # Initialize components
    mcp_client = MCPClient(config)
    data_collector = DataCollector(config, mcp_client)
    baseline_tracker = BaselineTracker(config)
    hypothesis_engine = HypothesisEngine()
    hunt_analyzer = HuntAnalyzer(config, mcp_client)
    telegram = TelegramNotifier(config)
    queue_reader = InvestigationQueueReader(
        config.investigation_queue_path,
        poll_interval=config.investigation_queue_poll_seconds,
    )

    # Test MCP connection
    logger.info("🔌 Testing MCP connection to %s ...", config.mcp_server_url)
    if mcp_client.test_connection():
        logger.info("✅ MCP connection successful!")
    else:
        logger.error("❌ MCP connection failed! Check server URL and connectivity.")
        logger.error("   Continuing anyway — will retry during hunt sessions.")

    last_scheduled_hunt = 0.0  # epoch time of last scheduled hunt

    try:
        logger.info("🔄 Entering dual-mode loop (queue watch + scheduled hunt)...")

        while not _shutdown_requested:
            # ── Priority 1: Check investigation queue from AI Alert ───────
            alert_requests = queue_reader.poll()

            if alert_requests:
                logger.info(
                    "📨 Received %d investigation request(s) from AI Alert!",
                    len(alert_requests),
                )
                run_alert_investigation(
                    config=config,
                    alert_requests=alert_requests,
                    mcp_client=mcp_client,
                    data_collector=data_collector,
                    hypothesis_engine=hypothesis_engine,
                    hunt_analyzer=hunt_analyzer,
                    telegram=telegram,
                )

            # ── Priority 2: Run scheduled hunt if interval has elapsed ────
            now = time.time()
            time_since_last_hunt = now - last_scheduled_hunt

            if time_since_last_hunt >= config.hunt_interval_seconds:
                run_hunt_session(
                    config=config,
                    mcp_client=mcp_client,
                    data_collector=data_collector,
                    baseline_tracker=baseline_tracker,
                    hypothesis_engine=hypothesis_engine,
                    hunt_analyzer=hunt_analyzer,
                    telegram=telegram,
                )
                last_scheduled_hunt = time.time()

                next_hunt_in = config.hunt_interval_seconds
                logger.info(
                    "⏰ Next scheduled hunt in %d seconds (%d hours).",
                    next_hunt_in, next_hunt_in // 3600,
                )

            # ── Sleep briefly before next poll cycle ──────────────────────
            # Short sleep to remain responsive to queue events
            sleep_duration = min(
                config.investigation_queue_poll_seconds,
                max(0, config.hunt_interval_seconds - (time.time() - last_scheduled_hunt)),
            )
            if not _shutdown_requested and sleep_duration > 0:
                time.sleep(sleep_duration)

    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received.")
    finally:
        logger.info("Shutting down Threat Hunter...")
        hunt_analyzer.close()
        mcp_client.close()
        telegram.close()
        logger.info("Goodbye! 👋")


if __name__ == "__main__":
    main()
