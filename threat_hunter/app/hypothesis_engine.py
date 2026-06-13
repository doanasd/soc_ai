from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List

from .models import (
    HuntDataset,
    HuntHypothesis,
    HypothesisSeverity,
)

logger = logging.getLogger(__name__)


class HypothesisEngine:
    """
    Generates threat hunting hypotheses from anomaly reports and overview data.

    Takes the output of BaselineTracker.detect_anomalies() plus the HuntDataset
    and produces structured HuntHypothesis objects for the AI agent to investigate.
    """

    # Mapping from anomaly type to hypothesis template
    ANOMALY_TEMPLATES: Dict[str, Dict[str, Any]] = {
        "volume_spike": {
            "category": "volumetric_anomaly",
            "title_template": "Abnormal log volume spike detected ({ratio}x baseline)",
            "description_template": (
                "Total log volume has spiked to {ratio}x the historical baseline. "
                "This could indicate a DDoS attack, mass scanning, brute-force campaign, "
                "or a misconfiguration causing log flooding. "
                "Investigate the top source IPs and destination ports to determine the cause."
            ),
            "suggested_queries": [
                'action:"block" AND network.source_ip:"{top_ip}"',
                'log_type:"{dominant_type}"',
            ],
        },
        "volume_drop": {
            "category": "logging_anomaly",
            "title_template": "Suspicious log volume drop to {ratio}x baseline",
            "description_template": (
                "Log volume has dropped significantly. This could indicate a logging "
                "pipeline failure, a compromised system suppressing logs, or a network "
                "issue preventing log delivery. Investigate whether all log sources are "
                "still reporting."
            ),
            "suggested_queries": [
                'log_type:"waf"',
                'log_type:"vpc"',
                'log_type:"linux"',
            ],
        },
        "log_type_spike": {
            "category": "targeted_attack",
            "title_template": "Log type '{log_type}' volume spike ({ratio}x baseline)",
            "description_template": (
                "The '{log_type}' log type has shown a {ratio}x increase in volume "
                "compared to the baseline. This may indicate a focused attack or "
                "scanning campaign targeting systems generating these logs."
            ),
            "suggested_queries": [
                'log_type:"{log_type}" AND action:"block"',
                'log_type:"{log_type}"',
            ],
        },
        "action_spike": {
            "category": "policy_violation",
            "title_template": "Action '{action}' volume spike ({ratio}x baseline)",
            "description_template": (
                "The '{action}' action has spiked to {ratio}x the baseline. "
                "If this is 'block', it may indicate increased attack activity. "
                "If 'allow', it could suggest successful unauthorized access."
            ),
            "suggested_queries": [
                'action:"{action}"',
            ],
        },
        "sensitive_port_activity": {
            "category": "reconnaissance",
            "title_template": "High activity on sensitive port {port}",
            "description_template": (
                "Detected {count:,} events targeting sensitive port {port}. "
                "This could indicate brute-force attacks (SSH/RDP), database exploitation "
                "attempts, or unauthorized service access."
            ),
            "suggested_queries": [
                'network.destination_port:"{port}" AND action:"allow"',
                'network.destination_port:"{port}" AND action:"block"',
            ],
        },
        "new_log_type": {
            "category": "new_threat_surface",
            "title_template": "New log type '{log_type}' appeared ({current:,} events)",
            "description_template": (
                "A previously unseen log type '{log_type}' has appeared with "
                "{current:,} events. This could indicate a new service deployment, "
                "a new attack vector, or a configuration change."
            ),
            "suggested_queries": [
                'log_type:"{log_type}"',
            ],
        },
    }

    def generate_hypotheses(
        self,
        dataset: HuntDataset,
        anomalies: List[Dict[str, Any]],
    ) -> List[HuntHypothesis]:
        """
        Generate hypotheses from detected anomalies.

        Returns a list of HuntHypothesis, sorted by severity (critical first).
        """
        hypotheses: List[HuntHypothesis] = []

        for anomaly in anomalies:
            hypothesis = self._anomaly_to_hypothesis(anomaly, dataset)
            if hypothesis:
                hypotheses.append(hypothesis)

        # If no anomalies but there's data, generate a general sweep hypothesis
        if not anomalies and dataset.total_logs > 0:
            hypotheses.append(self._general_sweep_hypothesis(dataset))

        # Sort by severity
        severity_order = {
            HypothesisSeverity.CRITICAL: 0,
            HypothesisSeverity.HIGH: 1,
            HypothesisSeverity.MEDIUM: 2,
            HypothesisSeverity.LOW: 3,
        }
        hypotheses.sort(key=lambda h: severity_order.get(h.severity, 99))

        logger.info("Generated %d hypotheses from %d anomalies", len(hypotheses), len(anomalies))
        return hypotheses

    def _anomaly_to_hypothesis(
        self,
        anomaly: Dict[str, Any],
        dataset: HuntDataset,
    ) -> HuntHypothesis | None:
        """Convert a single anomaly into a HuntHypothesis."""
        anomaly_type = anomaly.get("type", "unknown")
        template = self.ANOMALY_TEMPLATES.get(anomaly_type)

        if not template:
            logger.warning("No template for anomaly type: %s", anomaly_type)
            return None

        details = anomaly.get("details", {})

        # Enrich details with dataset context
        if dataset.top_source_ips:
            details["top_ip"] = dataset.top_source_ips[0].key
        details["dominant_type"] = max(
            dataset.log_type_counts, key=dataset.log_type_counts.get  # type: ignore[arg-type]
        ) if dataset.log_type_counts else "unknown"

        # Format title and description
        try:
            title = template["title_template"].format(**details)
        except KeyError:
            title = template["title_template"]

        try:
            description = template["description_template"].format(**details)
        except KeyError:
            description = template["description_template"]

        # Format suggested queries
        suggested_queries = []
        for q_template in template.get("suggested_queries", []):
            try:
                suggested_queries.append(q_template.format(**details))
            except KeyError:
                suggested_queries.append(q_template)

        # Map anomaly severity
        severity_map = {
            "critical": HypothesisSeverity.CRITICAL,
            "high": HypothesisSeverity.HIGH,
            "medium": HypothesisSeverity.MEDIUM,
            "low": HypothesisSeverity.LOW,
        }
        severity = severity_map.get(
            anomaly.get("severity", "medium"),
            HypothesisSeverity.MEDIUM,
        )

        return HuntHypothesis(
            id=f"hyp_{anomaly_type}_{uuid.uuid4().hex[:6]}",
            title=title,
            description=description,
            severity=severity,
            category=template["category"],
            suggested_queries=suggested_queries,
            anomaly_details=details,
        )

    def _general_sweep_hypothesis(self, dataset: HuntDataset) -> HuntHypothesis:
        """Generate a baseline sweep hypothesis when no anomalies are detected."""
        top_ips_info = ", ".join(
            f"{e.key} ({e.count})" for e in dataset.top_source_ips[:5]
        )

        return HuntHypothesis(
            id=f"hyp_general_sweep_{uuid.uuid4().hex[:6]}",
            title="Routine threat sweep — no anomalies detected",
            description=(
                f"No significant anomalies detected in the last {dataset.lookback_hours}h. "
                f"Total logs: {dataset.total_logs:,}. "
                f"Top source IPs: {top_ips_info or 'N/A'}. "
                f"Perform a routine check for low-and-slow attacks, "
                f"credential stuffing, or subtle lateral movement that may not "
                f"trigger volumetric anomalies."
            ),
            severity=HypothesisSeverity.LOW,
            category="routine_sweep",
            suggested_queries=[
                'action:"allow" AND network.destination_port:"22"',
                'action:"allow" AND network.destination_port:"3389"',
                'log_type:"linux" AND action:"failed"',
            ],
        )

    # ── Alert-driven hypothesis generation ───────────────────────────────

    # Map AI Alert categories to suggested OpenSearch queries
    ALERT_CATEGORY_QUERIES: Dict[str, List[str]] = {
        "brute_force": [
            'action:"block" AND network.destination_port:"22"',
            'action:"allow" AND network.destination_port:"22"',
            'log_type:"linux" AND action:"ssh_login_failed"',
        ],
        "port_scan": [
            'action:"block"',
            'action:"reject"',
        ],
        "web_attack": [
            'log_type:"waf" AND action:"block"',
            'log_type:"waf" AND action:"allow"',
        ],
        "data_exfiltration": [
            'action:"allow" AND network.destination_port:"443"',
            'action:"allow" AND network.destination_port:"53"',
        ],
        "credential_stuffing": [
            'log_type:"waf" AND action:"block"',
            'action:"allow" AND network.destination_port:"443"',
        ],
        "ddos": [
            'log_type:"waf" AND action:"block"',
            'log_type:"vpc" AND action:"reject"',
        ],
        "lateral_movement": [
            'action:"allow" AND network.destination_port:"445"',
            'action:"allow" AND network.destination_port:"3389"',
            'action:"allow" AND network.destination_port:"5985"',
        ],
    }

    def from_alert_request(
        self, alert_request: Dict[str, Any],
    ) -> HuntHypothesis:
        """
        Convert an AI Alert investigation request into a HuntHypothesis.

        This is the bridge between AI Alert (detection) and Threat Hunter
        (investigation). The alert summary provides the initial context,
        and the Threat Hunter will use MCP to query raw logs for evidence.
        """
        severity_map = {
            "critical": HypothesisSeverity.CRITICAL,
            "high": HypothesisSeverity.HIGH,
            "medium": HypothesisSeverity.MEDIUM,
            "low": HypothesisSeverity.LOW,
        }
        severity = severity_map.get(
            alert_request.get("alert_severity", "medium"),
            HypothesisSeverity.MEDIUM,
        )

        category = alert_request.get("alert_category", "unknown")
        title = alert_request.get("alert_title", "AI Alert Investigation")
        summary = alert_request.get("alert_summary", "")
        reasoning = alert_request.get("alert_reasoning", "")

        # Build context-rich description for the AI agent
        window_summary = alert_request.get("window_summary", {})
        top_ips = window_summary.get("top_source_ips", [])
        top_ips_str = ", ".join(
            f"{ip.get('ip', '?')} ({ip.get('count', '?')})" for ip in top_ips[:5]
        ) or "N/A"

        description = (
            f"[ALERT-TRIGGERED INVESTIGATION]\n"
            f"AI Alert has flagged a {severity.value.upper()} severity incident.\n\n"
            f"Alert: {title}\n"
            f"Category: {category}\n"
            f"Summary: {summary}\n\n"
            f"AI Reasoning: {reasoning}\n\n"
            f"Window context:\n"
            f"  - Dominant log type: {window_summary.get('dominant_log_type', 'N/A')}\n"
            f"  - Dominant action: {window_summary.get('dominant_action', 'N/A')}\n"
            f"  - Log type counts: {window_summary.get('log_type_counts', {})}\n"
            f"  - Top source IPs: {top_ips_str}\n\n"
            f"Use MCP to query raw logs and determine if this is a real threat "
            f"or a false positive. Look for corroborating evidence, attack patterns, "
            f"and assess the actual impact."
        )

        # Build suggested queries from category + top IPs
        suggested_queries = list(self.ALERT_CATEGORY_QUERIES.get(category, []))
        for ip_entry in top_ips[:3]:
            ip = ip_entry.get("ip", "")
            if ip:
                suggested_queries.append(f'network.source_ip:"{ip}"')

        return HuntHypothesis(
            id=f"hyp_alert_{category}_{uuid.uuid4().hex[:6]}",
            title=f"[Alert Investigation] {title}",
            description=description,
            severity=severity,
            category=category,
            suggested_queries=suggested_queries,
            anomaly_details={
                "source": "ai_alert",
                "dedup_key": alert_request.get("dedup_key", ""),
                "confidence": alert_request.get("alert_confidence", 50),
                "recommended_actions": alert_request.get("recommended_actions", []),
                "window_summary": window_summary,
            },
        )


__all__ = ["HypothesisEngine"]
