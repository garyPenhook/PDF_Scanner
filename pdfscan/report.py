from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Iterable

from .models import ScanFinding


class JsonlWriter:
    def __init__(self, path: Path, *, fsync: bool = False) -> None:
        self.path = path
        self.fsync = fsync
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("a", encoding="utf-8")

    def write(self, finding: ScanFinding) -> None:
        self._fh.write(json.dumps(finding.to_json(), sort_keys=True) + "\n")
        self._fh.flush()
        if self.fsync:
            import os

            os.fsync(self._fh.fileno())

    def close(self) -> None:
        self._fh.close()


def write_summary_csv(path: Path, findings: Iterable[ScanFinding]) -> None:
    rows = list(findings)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["path", "sha256", "verdict", "score", "top_reason"])
        for finding in rows:
            writer.writerow(
                [
                    finding.path,
                    finding.sha256 or "",
                    finding.verdict,
                    finding.score,
                    finding.reasons[0] if finding.reasons else "",
                ]
            )


def write_markdown(path: Path, findings: Iterable[ScanFinding], run_info: dict) -> None:
    rows = list(findings)
    counts = Counter(f.verdict for f in rows)
    lines = [
        "# PDF Scan Report",
        "",
        f"- Started: {run_info.get('started')}",
        f"- Finished: {run_info.get('finished')}",
        f"- Host: {run_info.get('host')}",
        f"- Files scanned: {len(rows)}",
        f"- ClamAV: {run_info.get('clamav_status')}",
        "",
        "## Verdict Counts",
        "",
    ]
    for verdict in ("critical", "high", "suspicious", "low", "unknown", "no_findings"):
        lines.append(f"- {verdict}: {counts.get(verdict, 0)}")
    for verdict in ("critical", "high", "suspicious", "unknown", "low", "no_findings"):
        group = [f for f in rows if f.verdict == verdict]
        if not group:
            continue
        lines.extend(["", f"## {verdict}", ""])
        for finding in sorted(group, key=lambda item: item.score, reverse=True)[:100]:
            lines.append(f"### `{finding.path}`")
            lines.append("")
            lines.append(f"- Score: {finding.score}")
            lines.append(f"- SHA-256: `{finding.sha256 or 'unknown'}`")
            lines.append(f"- Reasons: {', '.join(finding.reasons) if finding.reasons else 'none'}")
            if finding.evidence_dir:
                lines.append(f"- Evidence: `{finding.evidence_dir}`")
            lines.append("")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_run_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
