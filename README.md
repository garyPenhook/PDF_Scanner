# PDF Malware Scanner

Defensive CLI scanner for PDF triage. It recursively discovers PDF files, runs raw lexical heuristics with PDF name de-obfuscation, scores suspicious structures and active content, optionally uses YARA and ClamAV, stores evidence outside the scanned tree, and writes JSONL, CSV, Markdown, and run metadata.

## Quick Start

```bash
./scan.sh
```

With no path arguments, `scan.sh` searches common local roots: `/home`, `/root`,
`/tmp`, `/var/tmp`, `/opt`, `/srv`, `/media`, and `/mnt`, limited by the
permissions of the user running the command. Use `--full-system` to scan from `/`.

To scan a narrower path:

```bash
./scan.py ~/Downloads --out-dir ./pdfscan-report --no-yara --no-clamav
```

`--jobs N` runs file scans across multiple worker processes. It defaults to up
to 8 CPU cores, based on the host CPU count.

Optional integrations:

```bash
python3 -m pip install --user -e ".[deep,yara,test]"
```

`pikepdf` enables deeper object walking and embedded-file extraction. `yara-python` enables bundled and custom YARA rules. ClamAV is discovered automatically from `clamd.conf`, common sockets, TCP config, or `clamscan`.

Optional CUDA acceleration is used only where it fits the workload today: large
non-image stream entropy checks. Install the GPU extra and leave GPU mode on
`auto`:

```bash
python3 -m pip install --user -e ".[gpu]"
./scan.py ~/Downloads --gpu auto
```

If no compatible CUDA/Numba stack is available, the scanner keeps using the CPU
path and records the reason in `run.json`.

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
