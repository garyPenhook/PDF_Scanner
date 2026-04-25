from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .util import ensure_private_dir


class EvidenceStore:
    def __init__(self, root: Path, sha256: str) -> None:
        self.root = root / sha256
        ensure_private_dir(self.root)

    def relative_to(self, base: Path) -> str:
        return self.root.relative_to(base).as_posix() + "/"

    def write_text(self, name: str, content: str) -> Path:
        path = self.root / name
        path.write_text(content, encoding="utf-8", errors="replace")
        return path

    def write_json(self, name: str, payload: Any) -> Path:
        path = self.root / name
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def append_jsonl(self, name: str, payload: Any) -> Path:
        path = self.root / name
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, sort_keys=True) + "\n")
        return path
