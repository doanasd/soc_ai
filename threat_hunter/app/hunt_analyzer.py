from __future__ import annotations

import json
import logging
import re
import time
import uuid
from typing import Any, Dict, List, Optional

import httpx  # type: ignore[import-not-found]

from .config import HuntConfig
from .mcp_client import MCPClient
from .models import (
    AgentStep,
    AgentToolCall,
    FindingVerdict,
    HuntDataset,
    HuntFinding,
    HuntHypothesis,
    HypothesisSeverity,
)
from .prompt_builder import (
    build_hypothesis_prompt,
    build_observation_prompt,
    build_system_prompt,
)

logger = logging.getLogger(__name__)


class HuntAnalyzer:
    """
    The AI Agent brain of the threat hunter.
    Implements a ReAct (Reason + Act) loop:

    1. Receive a HuntHypothesis + context
    2. Send to LLM with system prompt describing available tools
    3. Parse LLM response for actions (search queries)
    4. Execute searches via MCP client
    5. Feed observations back to LLM
    6. Repeat until LLM concludes or max iterations reached
    7. Output a HuntFinding
    """

    def __init__(
        self,
        config: HuntConfig,
        mcp_client: MCPClient,
    ) -> None:
        self._config = config
        self._mcp = mcp_client
        self._groq_client = httpx.Client(
            base_url="https://api.groq.com/openai/v1",
            headers={
                "Authorization": f"Bearer {config.groq_api_key}",
                "Content-Type": "application/json",
            },
            timeout=config.groq_timeout_seconds,
        )

    def close(self) -> None:
        self._groq_client.close()

    def investigate(
        self,
        hypothesis: HuntHypothesis,
        dataset: HuntDataset,
        anomalies: List[Dict[str, Any]],
        session_id: str = "",
    ) -> HuntFinding:
        """
        Run the full ReAct investigation loop for a single hypothesis.
        Returns a HuntFinding with the verdict and evidence.
        """
        logger.info(
            "🔍 Starting investigation: [%s] %s",
            hypothesis.id, hypothesis.title,
        )

        max_iterations = self._config.max_tool_calls_per_hypothesis
        messages = self._build_initial_messages(hypothesis, dataset, anomalies)
        steps: List[AgentStep] = []
        queries_executed: List[str] = []
        tool_calls_made = 0

        for iteration in range(1, max_iterations + 1):
            logger.info("  → ReAct iteration %d/%d", iteration, max_iterations)

            # ── Call LLM ─────────────────────────────────────────────────────
            llm_response = self._call_llm(messages)
            if llm_response is None:
                logger.error("LLM call failed at iteration %d", iteration)
                break

            logger.debug("LLM response: %s", llm_response[:500])

            # ── Parse for action or conclusion ───────────────────────────────
            action = self._extract_action(llm_response)

            if action is None:
                # LLM provided text but no structured action — treat as final thought
                logger.info("  → No action extracted, treating as final response")
                break

            if action.get("action") == "conclude":
                # LLM is ready to conclude
                logger.info("  → LLM concluded: verdict=%s", action.get("verdict"))
                return self._build_finding_from_conclusion(
                    action, hypothesis, queries_executed, tool_calls_made, session_id,
                )

            if action.get("action") == "search":
                # Execute the search query
                query = action.get("query", "*")
                reasoning = action.get("reasoning", "")
                logger.info("  → Executing query: %s (reason: %s)", query, reasoning[:100])

                # Record step
                step = AgentStep(
                    step_number=iteration,
                    thought=reasoning,
                    action=AgentToolCall(
                        tool_name="search_logs",
                        query=query,
                        reasoning=reasoning,
                    ),
                )

                # Execute via MCP
                time_range = {
                    "gte": dataset.time_range_start or "now-24h",
                    "lte": dataset.time_range_end or "now",
                }
                result = self._mcp.search_logs(
                    query=query,
                    time_range=time_range,
                    size=self._config.max_log_results_per_query,
                )

                tool_calls_made += 1
                queries_executed.append(query)

                results = result.get("results", [])
                result_count = result.get("count", len(results))
                step.observation = f"Returned {result_count} results"
                steps.append(step)

                # Build observation and add to conversation
                observation_prompt = build_observation_prompt(
                    step_number=iteration,
                    query_executed=query,
                    results=results,
                    result_count=result_count,
                    max_display=20,
                )

                # Add assistant response + observation to messages
                messages.append({"role": "assistant", "content": llm_response})
                messages.append({"role": "user", "content": observation_prompt})

                logger.info(
                    "  → Got %d results for query: %s", result_count, query[:80],
                )
            else:
                logger.warning("  → Unknown action type: %s", action.get("action"))
                break

        # If we exhausted iterations or LLM didn't conclude, force a conclusion
        logger.info("  → Forcing conclusion after %d iterations", tool_calls_made)
        return self._force_conclusion(
            messages, hypothesis, queries_executed, tool_calls_made, session_id,
        )

    def _build_initial_messages(
        self,
        hypothesis: HuntHypothesis,
        dataset: HuntDataset,
        anomalies: List[Dict[str, Any]],
    ) -> List[Dict[str, str]]:
        """Build the initial message list for the LLM conversation."""
        system_prompt = build_system_prompt()
        user_prompt = build_hypothesis_prompt(hypothesis, dataset, anomalies)

        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

    def _call_llm(
        self, messages: List[Dict[str, str]], retries: int = 2
    ) -> Optional[str]:
        """Call the Groq API and return the text content."""
        if not self._config.groq_api_key:
            logger.error("GROQ_API_KEY not configured")
            return None

        payload = {
            "model": self._config.groq_model,
            "messages": messages,
            "temperature": 0.1,
            "max_tokens": self._config.groq_max_tokens,
        }

        backoff = 1.0
        for attempt in range(1, retries + 2):
            try:
                response = self._groq_client.post(
                    "/chat/completions", json=payload
                )
                response.raise_for_status()
                data = response.json()

                choices = data.get("choices", [])
                if not choices:
                    logger.error("Groq response has no choices")
                    return None

                content = choices[0].get("message", {}).get("content", "")

                # Log usage
                usage = data.get("usage", {})
                logger.info(
                    "LLM call: prompt=%d completion=%d total=%d",
                    usage.get("prompt_tokens", 0),
                    usage.get("completion_tokens", 0),
                    usage.get("total_tokens", 0),
                )

                return content

            except httpx.HTTPStatusError as exc:
                logger.error(
                    "Groq API error (attempt %d/%d, status=%d): %s",
                    attempt, retries + 1,
                    exc.response.status_code,
                    exc.response.text[:500],
                )
                if exc.response.status_code == 429:
                    # Rate limited — wait longer
                    time.sleep(backoff * 3)
                elif attempt <= retries:
                    time.sleep(backoff)
                backoff *= 2

            except httpx.RequestError:
                logger.exception(
                    "Groq request error (attempt %d/%d)", attempt, retries + 1,
                )
                if attempt <= retries:
                    time.sleep(backoff)
                backoff *= 2

        return None

    def _extract_action(self, llm_response: str) -> Optional[Dict[str, Any]]:
        """
        Extract a structured action JSON from the LLM response.
        The LLM is instructed to output actions as JSON objects.
        """
        # Try to find JSON blocks in the response
        # Pattern 1: ```json ... ```
        json_block_pattern = r'```(?:json)?\s*(\{[^`]*\})\s*```'
        matches = re.findall(json_block_pattern, llm_response, re.DOTALL)
        for match in matches:
            parsed = self._try_parse_json(match)
            if parsed and "action" in parsed:
                return parsed

        # Pattern 2: inline JSON on a single line
        inline_pattern = r'(\{"action"\s*:\s*"[^"]+?"[^}]*\})'
        matches = re.findall(inline_pattern, llm_response, re.DOTALL)
        for match in matches:
            parsed = self._try_parse_json(match)
            if parsed and "action" in parsed:
                return parsed

        # Pattern 3: Look for any JSON object in the response
        brace_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
        matches = re.findall(brace_pattern, llm_response, re.DOTALL)
        for match in matches:
            parsed = self._try_parse_json(match)
            if parsed and "action" in parsed:
                return parsed

        return None

    @staticmethod
    def _try_parse_json(text: str) -> Optional[Dict[str, Any]]:
        """Attempt to parse text as JSON, return None on failure."""
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                return data
        except (json.JSONDecodeError, TypeError):
            pass
        return None

    def _build_finding_from_conclusion(
        self,
        conclusion: Dict[str, Any],
        hypothesis: HuntHypothesis,
        queries_executed: List[str],
        tool_calls_made: int,
        session_id: str,
    ) -> HuntFinding:
        """Build a HuntFinding from the LLM's conclusion JSON."""
        # Map verdict
        verdict_map = {
            "confirmed": FindingVerdict.CONFIRMED,
            "suspicious": FindingVerdict.SUSPICIOUS,
            "dismissed": FindingVerdict.DISMISSED,
            "inconclusive": FindingVerdict.INCONCLUSIVE,
        }
        verdict = verdict_map.get(
            conclusion.get("verdict", "inconclusive"),
            FindingVerdict.INCONCLUSIVE,
        )

        # Map severity
        severity_map = {
            "low": HypothesisSeverity.LOW,
            "medium": HypothesisSeverity.MEDIUM,
            "high": HypothesisSeverity.HIGH,
            "critical": HypothesisSeverity.CRITICAL,
        }
        severity = severity_map.get(
            conclusion.get("severity", hypothesis.severity.value),
            hypothesis.severity,
        )

        confidence = max(0, min(100, int(conclusion.get("confidence", 50))))

        return HuntFinding(
            id=f"finding_{uuid.uuid4().hex[:8]}",
            hypothesis_id=hypothesis.id,
            hypothesis_title=hypothesis.title,
            verdict=verdict,
            severity=severity,
            confidence=confidence,
            title=conclusion.get("title", f"Investigation: {hypothesis.title}"),
            summary=conclusion.get("summary", "No summary provided."),
            reasoning=conclusion.get("reasoning", ""),
            evidence=conclusion.get("evidence", []),
            recommended_actions=conclusion.get("recommended_actions", []),
            tool_calls_made=tool_calls_made,
            queries_executed=queries_executed,
            hunt_session_id=session_id,
        )

    def _force_conclusion(
        self,
        messages: List[Dict[str, str]],
        hypothesis: HuntHypothesis,
        queries_executed: List[str],
        tool_calls_made: int,
        session_id: str,
    ) -> HuntFinding:
        """
        Force the LLM to provide a conclusion when max iterations are exhausted.
        """
        force_prompt = """You have used all available query attempts. 
Based on ALL the evidence you've gathered so far, provide your FINAL CONCLUSION now.

Format your response as a single JSON object:
{"action": "conclude", "verdict": "confirmed|suspicious|dismissed|inconclusive", "severity": "low|medium|high|critical", "confidence": 0-100, "title": "<finding title>", "summary": "<detailed summary of what you found>", "reasoning": "<step-by-step reasoning based on evidence>", "evidence": ["<key evidence 1>", "<key evidence 2>"], "recommended_actions": ["<action 1>", "<action 2>"]}"""

        messages.append({"role": "user", "content": force_prompt})
        llm_response = self._call_llm(messages)

        if llm_response:
            action = self._extract_action(llm_response)
            if action and action.get("action") == "conclude":
                return self._build_finding_from_conclusion(
                    action, hypothesis, queries_executed, tool_calls_made, session_id,
                )

        # Absolute fallback — create an inconclusive finding
        return HuntFinding(
            id=f"finding_{uuid.uuid4().hex[:8]}",
            hypothesis_id=hypothesis.id,
            hypothesis_title=hypothesis.title,
            verdict=FindingVerdict.INCONCLUSIVE,
            severity=hypothesis.severity,
            confidence=20,
            title=f"Inconclusive: {hypothesis.title}",
            summary=(
                "The investigation could not reach a definitive conclusion. "
                "The LLM was unable to provide a structured verdict after "
                f"{tool_calls_made} tool calls."
            ),
            reasoning="Investigation exhausted available query attempts without clear conclusion.",
            evidence=[],
            recommended_actions=["Review manually", "Re-run with different parameters"],
            tool_calls_made=tool_calls_made,
            queries_executed=queries_executed,
            hunt_session_id=session_id,
        )


__all__ = ["HuntAnalyzer"]
