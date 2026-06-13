from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any, Dict, List, Optional

import httpx  # type: ignore[import-not-found]

from .config import HuntConfig

logger = logging.getLogger(__name__)


class MCPClient:
    """
    Client for communicating with the MCP (Model Context Protocol) server.
    Sends JSON-RPC 2.0 requests to invoke the SearchIndexTool on OpenSearch.

    Endpoint: http://10.10.10.20:9900/mcp/
    """

    def __init__(self, config: HuntConfig) -> None:
        self._config = config
        self._base_url = config.mcp_server_url.rstrip("/")
        self._tool_name = config.mcp_tool_name
        self._index_pattern = config.opensearch_index_pattern
        self._max_results = config.max_log_results_per_query
        self._client = httpx.Client(
            timeout=config.groq_timeout_seconds,
            headers={"Content-Type": "application/json"},
        )

    def close(self) -> None:
        self._client.close()

    def _make_request_id(self) -> str:
        return str(uuid.uuid4())[:8]

    def execute_tool(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        retries: int = 2,
    ) -> Dict[str, Any]:
        """
        Execute a tool via MCP JSON-RPC 2.0 protocol.

        The MCP server expects:
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "<tool_name>",
                "arguments": { ... }
            },
            "id": "<request_id>"
        }
        """
        payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
            "id": self._make_request_id(),
        }

        backoff = 1.0
        last_error: Optional[Exception] = None

        for attempt in range(1, retries + 2):
            try:
                logger.debug(
                    "MCP request (attempt %d/%d): %s",
                    attempt, retries + 1,
                    json.dumps(payload, ensure_ascii=False)[:500],
                )
                response = self._client.post(self._base_url, json=payload)
                response.raise_for_status()

                data = response.json()

                # Check for JSON-RPC error
                if "error" in data:
                    error_info = data["error"]
                    logger.error(
                        "MCP JSON-RPC error: code=%s message=%s",
                        error_info.get("code"),
                        error_info.get("message"),
                    )
                    return {"error": error_info, "results": []}

                # Extract result
                result = data.get("result", {})
                return self._parse_tool_result(result)

            except httpx.HTTPStatusError as exc:
                last_error = exc
                logger.error(
                    "MCP HTTP error (attempt %d/%d, status=%d): %s",
                    attempt, retries + 1,
                    exc.response.status_code,
                    exc.response.text[:500],
                )
            except httpx.RequestError as exc:
                last_error = exc
                logger.error(
                    "MCP request error (attempt %d/%d): %s",
                    attempt, retries + 1, str(exc),
                )
            except Exception as exc:
                last_error = exc
                logger.exception(
                    "Unexpected MCP error (attempt %d/%d)", attempt, retries + 1,
                )

            if attempt <= retries:
                time.sleep(backoff)
                backoff *= 2

        logger.error("MCP request failed after %d attempts: %s", retries + 1, last_error)
        return {"error": str(last_error), "results": []}

    def _parse_tool_result(self, result: Any) -> Dict[str, Any]:
        """
        Parse the MCP tool result.
        The result may contain:
        - Direct JSON array of log hits
        - A 'content' field with text/json items
        - Aggregation results
        """
        if isinstance(result, dict):
            # MCP standard: result has "content" array
            content_list = result.get("content", [])
            if isinstance(content_list, list):
                parsed_results = []
                for item in content_list:
                    if isinstance(item, dict):
                        text = item.get("text", "")
                        if text:
                            try:
                                parsed = json.loads(text)
                                if isinstance(parsed, list):
                                    parsed_results.extend(parsed)
                                elif isinstance(parsed, dict):
                                    parsed_results.append(parsed)
                            except json.JSONDecodeError:
                                parsed_results.append({"raw_text": text})
                        elif "data" in item:
                            parsed_results.append(item["data"])
                if parsed_results:
                    return {"results": parsed_results, "count": len(parsed_results)}

            # Maybe result itself has hits
            if "hits" in result:
                hits = result["hits"]
                if isinstance(hits, dict):
                    hit_list = hits.get("hits", [])
                    return {"results": hit_list, "count": len(hit_list), "total": hits.get("total")}
                elif isinstance(hits, list):
                    return {"results": hits, "count": len(hits)}

            # Aggregation results
            if "aggregations" in result:
                return {"results": [], "aggregations": result["aggregations"], "count": 0}

            return {"results": [result], "count": 1}

        elif isinstance(result, list):
            return {"results": result, "count": len(result)}

        return {"results": [], "count": 0}

    # ── High-level Wrappers ──────────────────────────────────────────────────

    def search_logs(
        self,
        query: str,
        time_range: Optional[Dict[str, str]] = None,
        size: Optional[int] = None,
        index: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Search raw logs using the SearchIndexTool.

        Args:
            query: OpenSearch query string (Lucene/KQL syntax)
            time_range: Optional {"gte": "now-24h", "lte": "now"} for @timestamp filter
            size: Number of results to return
            index: Index pattern (defaults to config)
        """
        effective_size = min(size or self._max_results, self._max_results)
        effective_index = index or self._index_pattern

        # Build OpenSearch DSL query
        search_body: Dict[str, Any] = {
            "size": effective_size,
            "sort": [{"@timestamp": {"order": "desc"}}],
        }

        # Build query part
        if time_range:
            search_body["query"] = {
                "bool": {
                    "must": [
                        {"query_string": {"query": query}},
                    ],
                    "filter": [
                        {"range": {"@timestamp": time_range}},
                    ],
                }
            }
        else:
            search_body["query"] = {
                "query_string": {"query": query}
            }

        arguments = {
            "index": effective_index,
            "body": json.dumps(search_body, ensure_ascii=False),
        }

        return self.execute_tool(self._tool_name, arguments)

    def get_aggregations(
        self,
        agg_body: Dict[str, Any],
        query: str = "*",
        time_range: Optional[Dict[str, str]] = None,
        index: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute an aggregation query on OpenSearch.

        Args:
            agg_body: The "aggs" portion of the query DSL
            query: Base query to filter logs (default: all)
            time_range: Time filter
            index: Index pattern
        """
        effective_index = index or self._index_pattern

        search_body: Dict[str, Any] = {
            "size": 0,  # We only want aggregation results
            "aggs": agg_body,
        }

        if time_range:
            search_body["query"] = {
                "bool": {
                    "must": [{"query_string": {"query": query}}],
                    "filter": [{"range": {"@timestamp": time_range}}],
                }
            }
        else:
            search_body["query"] = {"query_string": {"query": query}}

        arguments = {
            "index": effective_index,
            "body": json.dumps(search_body, ensure_ascii=False),
        }

        return self.execute_tool(self._tool_name, arguments)

    def test_connection(self) -> bool:
        """Quick test: search for 1 doc to verify connectivity."""
        try:
            result = self.search_logs(query="*", size=1)
            if "error" in result and result["error"]:
                logger.error("MCP connection test failed: %s", result["error"])
                return False
            logger.info("MCP connection test OK. Got %d result(s).", result.get("count", 0))
            return True
        except Exception:
            logger.exception("MCP connection test failed")
            return False


__all__ = ["MCPClient"]
