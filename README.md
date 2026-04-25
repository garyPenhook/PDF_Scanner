# PDF Malware Scanner

Defensive CLI scanner for PDF triage. It recursively discovers PDF files, runs raw lexical heuristics with PDF name de-obfuscation, scores suspicious structures and active content, optionally uses YARA and ClamAV, stores evidence outside the scanned tree, and writes JSONL, CSV, Markdown, and run metadata.

## Quick Start

```bash
./scan.py ~/Downloads --out-dir ./pdfscan-report --no-yara --no-clamav
```

Optional integrations:

```bash
python3 -m pip install --user -e ".[deep,yara,test]"
```

`pikepdf` enables deeper object walking and embedded-file extraction. `yara-python` enables bundled and custom YARA rules. ClamAV is discovered automatically from `clamd.conf`, common sockets, TCP config, or `clamscan`.

## Outputs

- `findings.jsonl` is streamed one record per scanned PDF.
- `summary.csv` contains path, hash, verdict, score, and top reason.
- `report.md` groups findings by verdict.
- `run.json` records scanner version, host, integration status, and counts.
- `evidence/<sha256>/` contains raw token counts, JavaScript snippets, URIs, and embedded-file metadata.
- `quarantine/` is only written when `--quarantine-mode copy|hardlink` is selected.

## Tests

```bash
python3 -m pytest -q
```
