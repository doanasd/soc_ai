from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .models import Event

logger = logging.getLogger(__name__)


@dataclass
class ContextDocument:
    name: str
    path: Path
    content: str
    mtime: float


class ContextLoader:
    """Load and cache analyst markdown context from a directory."""

    def __init__(self, context_dir: Path, max_chars: int) -> None:
        self._context_dir = context_dir
        self._max_chars = max_chars
        self._docs: Dict[str, ContextDocument] = {}

    def _load_file(self, path: Path) -> Optional[ContextDocument]:
        try:
            stat = path.stat()
        except FileNotFoundError:
            return None

        mtime = stat.st_mtime
        cached = self._docs.get(path.name)
        if cached and cached.mtime == mtime:
            return cached

        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            logger.exception("Failed to read context file %s", path)
            return None

        doc = ContextDocument(name=path.name, path=path, content=text, mtime=mtime)
        self._docs[path.name] = doc
        return doc

    def refresh(self) -> None:
        """Refresh known context documents from disk."""

        if not self._context_dir.exists():
            logger.warning("Context directory %s does not exist", self._context_dir)
            return

        for path in sorted(self._context_dir.glob("*.md")):
            self._load_file(path)

    def _select_docs_for_event(self, event: Event) -> List[ContextDocument]:
        """Simple heuristic selection based on event fields."""

        selected: List[ContextDocument] = []
        name_map = {name: doc for name, doc in self._docs.items()}

        def maybe_add(filename: str) -> None:
            doc = name_map.get(filename)
            if doc and doc not in selected:
                selected.append(doc)

        # Always prefer baseline environment / detection policy
        maybe_add("01_environment.md")
        maybe_add("02_detection_policy.md")

        if event.log_type and "waf" in event.log_type.lower():
            maybe_add("04_known_benign_patterns.md")

        if event.action and event.action.lower() in {"blocked", "denied"}:
            maybe_add("04_known_benign_patterns.md")

        if event.rule_id:
            maybe_add("03_asset_criticality.md")

        maybe_add("05_response_playbooks.md")
        maybe_add("06_output_schema.md")

        # Fallback: include any other docs until we hit size limit
        for doc in name_map.values():
            if doc not in selected:
                selected.append(doc)

        return selected

    def build_context(self, event: Event) -> str:
        """Return a concatenated markdown context string suitable for prompting.

        Respects the max_chars limit and reloads files when they have changed on disk.
        """

        self.refresh()
        docs = self._select_docs_for_event(event)

        parts: List[str] = []
        remaining = self._max_chars

        for doc in docs:
            if remaining <= 0:
                break

            text = doc.content.strip()
            if not text:
                continue

            snippet = text[:remaining]
            parts.append(f"# {doc.name}\n\n{snippet}")
            remaining -= len(snippet)

        return "\n\n---\n\n".join(parts)

    def build_full_context(self) -> str:
        """Return a concatenated markdown context string using all documents."""

        self.refresh()
        docs = [self._docs[name] for name in sorted(self._docs)]

        parts: List[str] = []
        remaining = self._max_chars

        for doc in docs:
            if remaining <= 0:
                break

            text = doc.content.strip()
            if not text:
                continue

            snippet = text[:remaining]
            parts.append(f"# {doc.name}\n\n{snippet}")
            remaining -= len(snippet)

        return "\n\n---\n\n".join(parts)


__all__ = ["ContextLoader"]
