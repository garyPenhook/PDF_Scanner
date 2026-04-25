from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


Verdict = str


@dataclass(slots=True)
class FileRecord:
    path: Path
    realpath: Path
    stat: Any


@dataclass(slots=True)
class ScanContext:
    out_dir: Path
    evidence_dir: Path
    quarantine_dir: Path
    scan_started: str
    host: str
    scanner_version: str
    rules_version: str
    clamav_version: str | None = None


@dataclass(slots=True)
class ScanFinding:
    path: str
    realpath: str
    inode: int | None = None
    device: int | None = None
    uid: int | None = None
    gid: int | None = None
    mode: str | None = None
    mtime: str | None = None
    size: int | None = None
    sha256: str | None = None
    pdf_header_offset: int | None = None
    encrypted: bool = False
    parser_status: str = "not_run"
    tag_counts: dict[str, int] = field(default_factory=dict)
    yara_matches: list[str] = field(default_factory=list)
    clamav: dict[str, Any] = field(default_factory=dict)
    uri_count: int = 0
    embedded_count: int = 0
    score: int = 0
    verdict: Verdict = "unknown"
    reasons: list[str] = field(default_factory=list)
    evidence_dir: str | None = None
    timing_ms: dict[str, int] = field(default_factory=dict)
    scan_started: str | None = None
    scan_finished: str | None = None
    scanner_version: str | None = None
    rules_version: str | None = None
    clamav_version: str | None = None
    host: str | None = None
    error: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "scanner_version": self.scanner_version,
            "rules_version": self.rules_version,
            "clamav_version": self.clamav_version,
            "host": self.host,
            "scan_started": self.scan_started,
            "scan_finished": self.scan_finished,
            "path": self.path,
            "realpath": self.realpath,
            "inode": self.inode,
            "device": self.device,
            "uid": self.uid,
            "gid": self.gid,
            "mode": self.mode,
            "mtime": self.mtime,
            "size": self.size,
            "sha256": self.sha256,
            "ssdeep": None,
            "tlsh": None,
            "pdf_header_offset": self.pdf_header_offset,
            "encrypted": self.encrypted,
            "parser_status": self.parser_status,
            "tag_counts": self.tag_counts,
            "yara_matches": self.yara_matches,
            "clamav": self.clamav,
            "uri_count": self.uri_count,
            "embedded_count": self.embedded_count,
            "score": self.score,
            "verdict": self.verdict,
            "reasons": self.reasons,
            "evidence_dir": self.evidence_dir,
            "timing_ms": self.timing_ms,
            "error": self.error,
        }
