from __future__ import annotations

from pathlib import Path


def load_hashes(paths: list[Path]) -> set[str]:
    hashes: set[str] = set()
    for path in paths:
        path = path.expanduser()
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            token = line.strip().split("#", 1)[0].strip().lower()
            if len(token) == 64 and all(ch in "0123456789abcdef" for ch in token):
                hashes.add(token)
    return hashes
