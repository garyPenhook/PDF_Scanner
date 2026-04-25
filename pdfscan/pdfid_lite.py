from __future__ import annotations

from pathlib import Path

from .lex import INTERESTING_NAMES, scan_bytes, scan_file


def tag_counts_from_bytes(data: bytes) -> dict[str, int]:
    """Return normalized PDF name counts for PDFiD-style triage."""
    result = scan_bytes(data)
    return {name: result.tag_counts.get(name, 0) for name in INTERESTING_NAMES}


def tag_counts_from_file(path: Path) -> dict[str, int]:
    result = scan_file(path)
    return {name: result.tag_counts.get(name, 0) for name in INTERESTING_NAMES}
