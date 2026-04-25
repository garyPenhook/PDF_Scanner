from __future__ import annotations

from .config import load_config
from .scanner import run_scan


def main(argv: list[str] | None = None) -> int:
    config = load_config(argv)
    return run_scan(config)
