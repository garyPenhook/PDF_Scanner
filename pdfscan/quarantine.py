from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from .util import ensure_private_dir, utc_now


class Quarantine:
    def __init__(self, root: Path, mode: str) -> None:
        self.root = root
        self.mode = mode
        self.files = root / "files"
        if mode != "none":
            ensure_private_dir(self.files)
            ensure_private_dir(root)

    def store_pdf(
        self,
        source: Path,
        sha256: str,
        *,
        score: int,
        verdict: str,
        reasons: list[str],
    ) -> str | None:
        if self.mode == "none":
            return None
        stored = self.files / f"{sha256}.pdf"
        if not stored.exists():
            if self.mode == "hardlink":
                try:
                    os.link(source, stored)
                except OSError:
                    shutil.copy2(source, stored)
            else:
                shutil.copy2(source, stored)
            os.chmod(stored, 0o400)
        self._manifest(
            {
                "sha256": sha256,
                "original_path": source.as_posix(),
                "stored_path": stored.relative_to(self.root).as_posix(),
                "score": score,
                "verdict": verdict,
                "reasons": reasons,
                "stored_at": utc_now(),
            }
        )
        return stored.as_posix()

    def store_payload(self, data: bytes, sha256: str, metadata: dict) -> str | None:
        if self.mode == "none":
            return None
        stored = self.files / f"{sha256}.bin"
        if not stored.exists():
            stored.write_bytes(data)
            os.chmod(stored, 0o400)
        self._manifest({**metadata, "sha256": sha256, "stored_path": stored.relative_to(self.root).as_posix()})
        return stored.as_posix()

    def _manifest(self, payload: dict) -> None:
        with (self.root / "manifest.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, sort_keys=True) + "\n")
