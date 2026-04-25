import json
from pathlib import Path

from pdfscan.cli import main


def _write_pdf(path: Path, body: bytes) -> None:
    path.write_bytes(b"%PDF-1.4\n" + body + b"\n%%EOF\n")


def test_cli_scans_directory_and_writes_reports(tmp_path: Path) -> None:
    samples = tmp_path / "samples"
    samples.mkdir()
    _write_pdf(samples / "benign.pdf", b"1 0 obj << /Type /Catalog >> endobj\nxref")
    _write_pdf(
        samples / "suspicious.pdf",
        b"1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert('x')) >> >> endobj\nxref",
    )
    out_dir = tmp_path / "out"

    exit_code = main(
        [
            samples.as_posix(),
            "--out-dir",
            out_dir.as_posix(),
            "--no-yara",
            "--no-clamav",
            "--format",
            "jsonl,csv,md",
            "--full",
        ]
    )

    assert exit_code == 2
    records = [
        json.loads(line)
        for line in (out_dir / "findings.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert len(records) == 2
    suspicious = next(record for record in records if record["path"].endswith("suspicious.pdf"))
    assert suspicious["verdict"] == "suspicious"
    assert suspicious["tag_counts"]["/OpenAction"] == 1
    assert (out_dir / "summary.csv").exists()
    assert (out_dir / "report.md").exists()
    assert (out_dir / "run.json").exists()


def test_too_large_is_unknown(tmp_path: Path) -> None:
    sample = tmp_path / "large.pdf"
    _write_pdf(sample, b"x" * 200)
    out_dir = tmp_path / "out"

    exit_code = main(
        [
            sample.as_posix(),
            "--out-dir",
            out_dir.as_posix(),
            "--max-size",
            "10",
            "--no-yara",
            "--no-clamav",
        ]
    )

    assert exit_code == 4
    record = json.loads((out_dir / "findings.jsonl").read_text(encoding="utf-8").strip())
    assert record["verdict"] == "unknown"
    assert record["reasons"] == ["unknown_too_large"]
