from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


def append_jsonl(path: Path, obj: Dict[str, Any]) -> None:
    """Append a single JSON object as one line to the given file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, separators=(",", ":"), ensure_ascii=False))
        fh.write("\n")


__all__ = ["append_jsonl"]

