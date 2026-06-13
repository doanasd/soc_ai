"""Quick import test for all threat_hunter modules."""
import sys
sys.path.insert(0, ".")

try:
    from app.config import load_config
    print("[OK] config")

    from app.models import (
        HuntDataset, HuntHypothesis, HuntFinding, HuntSession,
        BaselineMetrics, AgentToolCall, AgentStep
    )
    print("[OK] models")

    from app.mcp_client import MCPClient
    print("[OK] mcp_client")

    from app.data_collector import DataCollector
    print("[OK] data_collector")

    from app.baseline_tracker import BaselineTracker
    print("[OK] baseline_tracker")

    from app.hypothesis_engine import HypothesisEngine
    print("[OK] hypothesis_engine")

    from app.prompt_builder import (
        build_system_prompt, build_hypothesis_prompt, build_observation_prompt
    )
    print("[OK] prompt_builder")

    from app.hunt_analyzer import HuntAnalyzer
    print("[OK] hunt_analyzer")

    from app.writers.jsonl_writer import append_finding
    print("[OK] jsonl_writer")

    from app.writers.telegram_writer import TelegramNotifier, format_finding_message
    print("[OK] telegram_writer")

    from app.main import run_hunt_session, main
    print("[OK] main")

    # Quick functional test: create objects
    config = load_config()
    print(f"\n[CONFIG] MCP URL: {config.mcp_server_url}")
    print(f"[CONFIG] Model: {config.groq_model}")
    print(f"[CONFIG] Interval: {config.hunt_interval_seconds}s")

    dataset = HuntDataset(total_logs=1000, log_type_counts={"waf": 500, "vpc": 300, "linux": 200})
    print(f"[MODEL] HuntDataset created: total={dataset.total_logs}")

    engine = HypothesisEngine()
    hypotheses = engine.generate_hypotheses(dataset, [])
    print(f"[ENGINE] Generated {len(hypotheses)} hypotheses (no anomalies)")

    prompt = build_system_prompt()
    print(f"[PROMPT] System prompt length: {len(prompt)} chars")

    print("\n=== ALL 11 MODULES IMPORTED AND TESTED SUCCESSFULLY ===")

except Exception as e:
    print(f"\n[FAIL] {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
