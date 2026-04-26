from __future__ import annotations

import json
import sqlite3
from contextlib import suppress
from pathlib import Path
from typing import Any


class ScanCache:
    def __init__(self, path: Path, enabled: bool = True) -> None:
        self.path = path
        self.enabled = enabled
        self._conn: sqlite3.Connection | None = None
        if enabled:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                self._conn = sqlite3.connect(path, timeout=30)
            except OSError:
                self.enabled = False
                self._conn = None
                return
            try:
                self._conn.execute("PRAGMA busy_timeout=30000")
                self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS seen (
                      sha256 TEXT NOT NULL,
                      scanner_version TEXT NOT NULL,
                      rules_version TEXT NOT NULL,
                      clamav_version TEXT NOT NULL,
                      payload TEXT NOT NULL,
                      PRIMARY KEY (sha256, scanner_version, rules_version, clamav_version)
                    )
                    """
                )
                self._conn.commit()
            except sqlite3.Error:
                self._disable()

    def get(
        self, sha256: str, scanner_version: str, rules_version: str, clamav_version: str
    ) -> dict[str, Any] | None:
        if self._conn is None:
            return None
        try:
            row = self._conn.execute(
                """
                SELECT payload FROM seen
                WHERE sha256=? AND scanner_version=? AND rules_version=? AND clamav_version=?
                """,
                (sha256, scanner_version, rules_version, clamav_version),
            ).fetchone()
        except sqlite3.Error:
            self._disable()
            return None
        return json.loads(row[0]) if row else None

    def put(
        self,
        sha256: str,
        scanner_version: str,
        rules_version: str,
        clamav_version: str,
        payload: dict[str, Any],
    ) -> None:
        if self._conn is None:
            return
        try:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO seen
                  (sha256, scanner_version, rules_version, clamav_version, payload)
                VALUES (?, ?, ?, ?, ?)
                """,
                (sha256, scanner_version, rules_version, clamav_version, json.dumps(payload)),
            )
            self._conn.commit()
        except sqlite3.Error:
            self._disable()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def _disable(self) -> None:
        self.enabled = False
        if self._conn is not None:
            with suppress(sqlite3.Error):
                self._conn.close()
            self._conn = None
