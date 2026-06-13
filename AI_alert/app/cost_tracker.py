from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _format_dt(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _format_money(value: float) -> str:
    return f"{value:.8f}"


def _format_rate(value: float) -> str:
    return f"{value:.6f}"


@dataclass(slots=True)
class ModelCallRecord:
    recorded_at: datetime
    model: str
    status: str
    prompt_tokens: int = 0
    cached_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    input_cost_usd: float = 0.0
    cached_input_cost_usd: float = 0.0
    output_cost_usd: float = 0.0
    total_cost_usd: float = 0.0
    http_status: Optional[int] = None

    def to_line(self) -> str:
        parts = [
            "CALL",
            _format_dt(self.recorded_at),
            f"model={self.model}",
            f"status={self.status}",
            f"http_status={self.http_status if self.http_status is not None else '-'}",
            f"prompt_tokens={self.prompt_tokens}",
            f"cached_tokens={self.cached_tokens}",
            f"completion_tokens={self.completion_tokens}",
            f"total_tokens={self.total_tokens}",
            f"input_cost_usd={_format_money(self.input_cost_usd)}",
            f"cached_input_cost_usd={_format_money(self.cached_input_cost_usd)}",
            f"output_cost_usd={_format_money(self.output_cost_usd)}",
            f"total_cost_usd={_format_money(self.total_cost_usd)}",
        ]
        return "\t".join(parts)

    @classmethod
    def from_line(cls, line: str) -> "ModelCallRecord":
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 3 or parts[0] != "CALL":
            raise ValueError("not a CALL line")

        recorded_at = datetime.fromisoformat(parts[1].replace("Z", "+00:00"))
        kv: Dict[str, str] = {}
        for item in parts[2:]:
            if "=" not in item:
                continue
            key, value = item.split("=", 1)
            kv[key] = value

        http_status_raw = kv.get("http_status", "-")
        return cls(
            recorded_at=recorded_at,
            model=kv.get("model", ""),
            status=kv.get("status", "unknown"),
            prompt_tokens=int(kv.get("prompt_tokens", "0")),
            cached_tokens=int(kv.get("cached_tokens", "0")),
            completion_tokens=int(kv.get("completion_tokens", "0")),
            total_tokens=int(kv.get("total_tokens", "0")),
            input_cost_usd=float(kv.get("input_cost_usd", "0")),
            cached_input_cost_usd=float(kv.get("cached_input_cost_usd", "0")),
            output_cost_usd=float(kv.get("output_cost_usd", "0")),
            total_cost_usd=float(kv.get("total_cost_usd", "0")),
            http_status=None if http_status_raw in {"", "-"} else int(http_status_raw),
        )


class ModelCostTracker:
    def __init__(
        self,
        report_path: Path,
        input_cost_per_million: float,
        cached_input_cost_per_million: float,
        output_cost_per_million: float,
    ) -> None:
        self._report_path = report_path
        self._input_cost_per_million = input_cost_per_million
        self._cached_input_cost_per_million = cached_input_cost_per_million
        self._output_cost_per_million = output_cost_per_million
        self._records: List[ModelCallRecord] = []
        self._load_existing()

    def _load_existing(self) -> None:
        if not self._report_path.exists():
            return

        records: List[ModelCallRecord] = []
        for line in self._report_path.read_text(encoding="utf-8").splitlines():
            if not line.startswith("CALL\t"):
                continue
            try:
                records.append(ModelCallRecord.from_line(line))
            except Exception:
                continue
        self._records = records

    def estimate_costs(
        self,
        prompt_tokens: int,
        cached_tokens: int,
        completion_tokens: int,
    ) -> Dict[str, float]:
        uncached_prompt_tokens = max(0, prompt_tokens - cached_tokens)
        input_cost_usd = (uncached_prompt_tokens / 1_000_000) * self._input_cost_per_million
        cached_input_cost_usd = (cached_tokens / 1_000_000) * self._cached_input_cost_per_million
        output_cost_usd = (completion_tokens / 1_000_000) * self._output_cost_per_million
        total_cost_usd = input_cost_usd + cached_input_cost_usd + output_cost_usd
        return {
            "input_cost_usd": input_cost_usd,
            "cached_input_cost_usd": cached_input_cost_usd,
            "output_cost_usd": output_cost_usd,
            "total_cost_usd": total_cost_usd,
        }

    def record_call(self, record: ModelCallRecord) -> Dict[str, Any]:
        self._records.append(record)
        self._write_report()
        return self.current_day_summary(now=record.recorded_at)

    def current_day_summary(self, now: Optional[datetime] = None) -> Dict[str, Any]:
        current_time = now or _utcnow()
        return self.summary_for_day(current_time.date())

    def summary_for_day(self, day: date) -> Dict[str, Any]:
        day_key = day.isoformat()
        selected = [
            record for record in self._records if record.recorded_at.date().isoformat() == day_key
        ]
        return self._build_day_summary(day_key, selected)

    def _build_day_summary(
        self, day_key: str, records: List[ModelCallRecord]
    ) -> Dict[str, Any]:
        return {
            "date": day_key,
            "calls": len(records),
            "successful_calls": sum(1 for record in records if record.status == "success"),
            "failed_calls": sum(1 for record in records if record.status != "success"),
            "prompt_tokens": sum(record.prompt_tokens for record in records),
            "cached_tokens": sum(record.cached_tokens for record in records),
            "completion_tokens": sum(record.completion_tokens for record in records),
            "total_tokens": sum(record.total_tokens for record in records),
            "input_cost_usd": sum(record.input_cost_usd for record in records),
            "cached_input_cost_usd": sum(record.cached_input_cost_usd for record in records),
            "output_cost_usd": sum(record.output_cost_usd for record in records),
            "total_cost_usd": sum(record.total_cost_usd for record in records),
        }

    def _write_report(self) -> None:
        self._report_path.parent.mkdir(parents=True, exist_ok=True)
        day_map: Dict[str, List[ModelCallRecord]] = {}
        for record in self._records:
            day_map.setdefault(record.recorded_at.date().isoformat(), []).append(record)

        lines = [
            "# Model Usage Cost Report",
            (
                "# Rates USD per 1M tokens: "
                f"input={_format_rate(self._input_cost_per_million)} "
                f"cached_input={_format_rate(self._cached_input_cost_per_million)} "
                f"output={_format_rate(self._output_cost_per_million)}"
            ),
            "",
            "# Daily Totals",
        ]

        for day_key in sorted(day_map):
            summary = self._build_day_summary(day_key, day_map[day_key])
            lines.append(
                "\t".join(
                    [
                        "DAY",
                        day_key,
                        f"calls={summary['calls']}",
                        f"successful_calls={summary['successful_calls']}",
                        f"failed_calls={summary['failed_calls']}",
                        f"prompt_tokens={summary['prompt_tokens']}",
                        f"cached_tokens={summary['cached_tokens']}",
                        f"completion_tokens={summary['completion_tokens']}",
                        f"total_tokens={summary['total_tokens']}",
                        f"input_cost_usd={_format_money(summary['input_cost_usd'])}",
                        f"cached_input_cost_usd={_format_money(summary['cached_input_cost_usd'])}",
                        f"output_cost_usd={_format_money(summary['output_cost_usd'])}",
                        f"total_cost_usd={_format_money(summary['total_cost_usd'])}",
                    ]
                )
            )

        lines.extend(["", "# Call History"])
        lines.extend(record.to_line() for record in self._records)
        self._report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


__all__ = ["ModelCallRecord", "ModelCostTracker"]
