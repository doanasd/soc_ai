from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from ..models import HuntFinding


def append_finding(path: Path, finding: HuntFinding) -> None:
    """Append a single HuntFinding as one JSON line to the given file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(
            json.dumps(
                finding.to_output_dict(),
                separators=(",", ":"),
                ensure_ascii=False,
            )
        )
        fh.write("\n")


__all__ = ["append_finding"]
