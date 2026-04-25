from pathlib import Path

from pdfscan.config import AppConfig
from pdfscan.discover import discover


def test_discovery_ignores_source_files_with_pdf_marker_text(tmp_path: Path) -> None:
    source = tmp_path / "test_source.py"
    source.write_bytes(b'data = b"%PDF-1.4\\n/JavaScript"\n')
    pdf = tmp_path / "real.pdf"
    pdf.write_bytes(b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n%%EOF\n")

    found = [record.path.name for record in discover(AppConfig(roots=[tmp_path]))]

    assert found == ["real.pdf"]


def test_discovery_allows_pdf_extension_polyglot(tmp_path: Path) -> None:
    polyglot = tmp_path / "polyglot.pdf"
    polyglot.write_bytes(b"junk before header\n%PDF-1.4\n%%EOF\n")

    found = [record.path.name for record in discover(AppConfig(roots=[tmp_path]))]

    assert found == ["polyglot.pdf"]
