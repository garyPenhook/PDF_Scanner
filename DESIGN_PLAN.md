# PDF Malware Scanner — Design Plan (Kali Linux), Revision 2

A defensive tool that recursively locates every PDF on a Kali Linux host and inspects each one for indicators of malicious content — embedded JavaScript, exploit-style object structures, dropper payloads, known malware signatures, suspicious URIs, obfuscated PDF names, and structural anomalies.

This is **revision 2**. It supersedes the original plan and incorporates review feedback covering YARA-in-multiprocessing, raw-vs-parsed scanning, honest verdicts, killable timeouts, ClamAV discovery, privilege separation, filesystem safety, quarantine hygiene, evidence storage, and forensic reporting.

---

## 1. Language Choice: Python (not Bash)

Python 3.11+. Bash is kept only as a thin cron / one-shot wrapper (`scan.sh`).

| Concern | Bash | Python |
|---|---|---|
| Recursive file discovery | Excellent (`find`) | Excellent (`os.walk` / `os.scandir`) |
| Native PDF structure parsing | None — must shell out | First-class (`pikepdf`/qpdf, `pdfminer.six`) |
| Raw lexical scanning of PDF tokens | Painful with `grep`/`awk` | Trivial with `re` on bytes |
| YARA / ClamAV / IOC integration | Brittle glue | Clean (`yara-python`, raw `clamd` socket) |
| Process-level isolation, killable timeouts | Coarse (`timeout`, `kill`) | Fine-grained (`multiprocessing` + `terminate()`) |
| Resource limits per worker | None | `resource.setrlimit` |
| Structured output (JSONL/CSV/SARIF) | Painful | Built-in |
| Risk scoring & combination rules | Hard | Easy |
| Tests | Rare | `pytest` |

---

## 2. Threat Model — What We Look For

### 2.1 Active content / code execution
`/JS`, `/JavaScript`, `/AA`, `/OpenAction`, `/Launch`, `/SubmitForm`, `/ImportData`, `/GoToR`, `/GoToE`, `/Named`, `/URI`, `/Sound`, `/Movie`, `/Rendition`, `/3D`, `/RichMedia`, `/Flash`, `/XFA`, `/AcroForm`, `/NeedAppearances`.

### 2.2 Payload delivery
`/EmbeddedFile`, `/ObjStm`, deeply stacked filters (`/FlateDecode`, `/ASCIIHexDecode`, `/ASCII85Decode`, `/LZWDecode`, `/JBIG2Decode`).

### 2.3 Obfuscation (must be normalized before keyword scoring)
PDF allows hex-escaped name characters: `/J#53` ≡ `/JS`, `/Java#53cript` ≡ `/JavaScript`, `/Open#41ction` ≡ `/OpenAction`. The raw lexical scanner normalizes every `#xx` sequence in a `/Name` token before counting. Detectors that skip normalization miss the most common evasion.

### 2.4 Structural anomalies
- `%PDF-` not at byte 0 → polyglot suspicion.
- More than one `%%EOF` → incremental update (often used to hide content).
- `obj` / `endobj` count mismatch.
- xref unparseable or missing → parser confusion.
- Very high entropy (Shannon ≥ 7.5) in non-image streams.
- Stream filter chain depth > 3.

### 2.5 Combination rules (more signal than raw keyword counts)
- `/OpenAction` + `/JavaScript`
- `/AA` + `/JavaScript`
- `/EmbeddedFile` + `/Launch`
- `/AcroForm` + `/XFA`
- `/RichMedia` + `/Flash`
- `/URI` + domain on local blocklist

### 2.6 Known-bad signatures
- ClamAV (PDF families and droppers).
- Vendored YARA rules (maldocs / exploit kits).
- Local SHA-256 IOC list.
- Optional fuzzy hash (ssdeep / TLSH) lookup.

---

## 3. Revised Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                          scan.py                             │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────────────────────────────┐
│ 1. Discover regular files (skip FIFOs, sockets, devices)     │
│ 2. Confirm PDF magic in first 1 KB                           │
│ 3. Hash + metadata (sha256, size, mtime, inode, dev, uid)    │
│ 4. Cache lookup (sqlite: ~/.cache/pdfscan/seen.db)           │
└──────────────┬───────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────┐
│ Cheap raw triage (in parent or short-lived worker):          │
│  - raw lexical token scan (with /#xx name normalization)     │
│  - structural heuristics (header offset, %%EOF count, xref)  │
│  - YARA raw-byte scan                                        │
└──────────────┬───────────────────────────────────────────────┘
               │
               ▼ (if suspicious OR --full)
┌──────────────────────────────────────────────────────────────┐
│ Deep scan in sandboxed worker process:                       │
│  - pikepdf parsed walk                                       │
│  - JS extraction → evidence file                             │
│  - URI extraction → evidence file                            │
│  - embedded file extraction → quarantine/files/<sha256>      │
│  - ClamAV INSTREAM scan of file + every embedded payload     │
│  - YARA scan of extracted JS                                 │
└──────────────┬───────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────┐
│ Score → verdict (incl. unknown bucket)                       │
│ Write JSONL immediately (crash-safe)                         │
│ Generate CSV + Markdown at end                               │
└──────────────────────────────────────────────────────────────┘
```

Writing `findings.jsonl` immediately (one line per file, fsync optional) means a crash, OOM-kill, or power loss mid-scan still leaves usable partial results.

### 3.1 File layout
```
PDF_Scanner/
├── DESIGN_PLAN.md
├── pyproject.toml
├── pdfscan.toml.example
├── scan.py                      # CLI entry
├── scan.sh                      # cron wrapper
├── install.sh
├── pdfscan/
│   ├── __init__.py
│   ├── config.py                # TOML config loader (file < CLI)
│   ├── discover.py              # walk, only regular files, exclusions
│   ├── hashing.py               # sha256, optional ssdeep/TLSH
│   ├── cache.py                 # sqlite cache
│   ├── lex.py                   # raw lexical scan + /#xx normalization
│   ├── pdfid_lite.py            # tag counts on normalized stream
│   ├── structure.py             # header offset, %%EOF, xref, entropy
│   ├── extractors.py            # pikepdf JS / EmbeddedFile / URI walk
│   ├── yara_engine.py           # compile to .yarc, per-worker load
│   ├── clamav_client.py         # discover + INSTREAM client + health
│   ├── scoring.py               # weights, combination rules, verdicts
│   ├── evidence.py              # writes evidence/<sha256>/*.txt
│   ├── quarantine.py            # copy/hardlink, manifest by sha256
│   ├── workers.py               # process pool with kill-on-timeout
│   ├── report.py                # JSONL (streamed), CSV, Markdown
│   └── rules/
│       ├── pdf_malicious.yar
│       └── ioc_hashes.txt
├── tests/
│   ├── samples/
│   │   ├── benign/
│   │   ├── inert_suspicious/    # built locally, no working payload
│   │   └── malformed/
│   └── test_*.py
```

---

## 4. Detection Layers

### 4.1 Discovery (`discover.py`)
- Scans only **regular files** (`stat.S_ISREG`). Skips FIFOs, sockets, char/block devices, broken symlinks.
- `--one-file-system` (default **on**) — never crosses mount points; avoids walking NFS shares, USB backups, Time-Machine-style mounts.
- Default exclusions: `/proc /sys /dev /run /tmp/.X11-unix /var/lib/docker /var/lib/containers /var/lib/lxc /var/lib/lxd /.snapshots /var/lib/clamav` plus the scanner's own out-dir and quarantine.
- `--include DIR`, `--exclude DIR`, `--exclude-regex REGEX`, `--max-depth N`.
- Symlinks not followed by default; `--follow-symlinks` allowed but symlink-loop guard via visited `(dev, inode)` set.
- Hardlink dedupe: `(dev, inode)` already seen → record once.
- Disappearing/unreadable files are caught and recorded as `unknown_io_error` rather than crashing the scan.
- Magic-byte filter: first 1 KB must contain `%PDF-` (catches polyglots; rejects renamed non-PDFs).

### 4.2 Cache (`cache.py`)
SQLite at `~/.cache/pdfscan/seen.db`, keyed on `(sha256, scanner_version, rules_version, clamav_db_time)`. A cache hit short-circuits to the prior verdict. Cache invalidates automatically when any of those fields change.

### 4.3 Raw lexical scan (`lex.py`) — runs **before** any parser
Treats the file as bytes. Two reasons it must come before `pikepdf`:

1. `pikepdf`/qpdf will repair malformed PDFs and can hide the very weirdness that made them suspicious.
2. Some evasions are visible only to a tokenizer (obfuscated names, junk between objects, multiple `%%EOF`).

Operations:
- Find `%PDF-` offset; offset > 0 → polyglot flag.
- Count `%%EOF`, `obj`, `endobj`, `stream`, `endstream`, `xref`, `trailer`.
- Walk every `/Name` token and normalize `#xx` hex escapes. Counts are taken on the **normalized** form so `/J#53` is counted as `/JS`.
- Collect filter names per stream dictionary (filter chain depth, suspicious filters).
- Produce a normalized tag-count vector (the `pdfid_lite` output).

### 4.4 Structural heuristics (`structure.py`)
- Header offset > 0.
- `%%EOF` count > 1 + JS present → boost.
- xref parseability (try/except via `pikepdf`).
- Per-stream Shannon entropy > 7.5 in non-image objects.
- Filter chain depth > 3.

### 4.5 Deep extraction (`extractors.py`) — only if triage says so, or `--full`
Parses with `pikepdf`:
- Walk every indirect object.
- Pull `/JS` and `/JavaScript` strings, decode escapes, write each one to `evidence/<sha256>/javascript_NNN.txt`. The Markdown report stores only a 200-char snippet — full JS lives on disk to keep reports safe to open.
- Score JS against an expanded pattern set:
  - `unescape(`, `app.alert`, `util.printf`, `Collab.collectEmailInfo`, `getAnnots`, `getIcon`, `media.newPlayer`
  - `eval(`, indirect eval (`this[...]`, `Function(`)
  - long `String.fromCharCode(...)` runs (heap spray)
  - long decimal arrays and large escaped Unicode blobs (`\u00xx` × N)
  - deep string concatenation (`+ + + +`)
  - AcroForm event JS (`/A`, `/AA` on form fields)
  - name-tree JS (`/Names /JavaScript`)
  - document-level JS (`/OpenAction` referencing JS)
- Pull every `/EmbeddedFile` stream, store at `quarantine/files/<sha256>.bin` (only when `--quarantine-mode` permits), record metadata in `evidence/<sha256>/embedded_files.jsonl`, re-scan each with ClamAV.
- Collect every `/URI` to `evidence/<sha256>/uri_list.txt`; check against local domain blocklist (e.g. URLhaus dump at `/var/lib/pdfscan/urlhaus.csv`).
- Cover all action types named in §2.1, not just JS-bearing ones.

### 4.6 YARA (`yara_engine.py`) — multiprocessing-safe
**Do not pickle `yara.Rules`.** It is a C-extension object and not reliably pickleable. Instead:

1. At startup the parent compiles every `.yar` under `pdfscan/rules/` (plus `--rules DIR`) into a single namespaced ruleset.
2. The parent saves the compiled ruleset to `<out-dir>/compiled_rules.yarc` via `rules.save(path)`.
3. Each worker, in its `initializer`, calls `yara.load(path)` once and stores the result in a module-level `WORKER_RULES`.
4. Per-file scans call `WORKER_RULES.match(...)` — no recompilation, no pickling.

Two passes per file:
- Raw bytes of the PDF.
- Concatenated extracted JavaScript (catches rules tuned for decoded payloads).

If a rule file fails to compile, the scanner logs and continues with the rest; it does not abort.

### 4.7 ClamAV (`clamav_client.py`)
**Discover the socket dynamically. Do not hardcode a path.**

Discovery order:
1. Parse `LocalSocket` from `/etc/clamav/clamd.conf` (and `/etc/clamd.conf` as a fallback).
2. Try `/var/run/clamav/clamd.ctl`.
3. Try `/run/clamav/clamd.ctl`.
4. Try TCP if `TCPSocket` is set.
5. Fall back to `subprocess.run(["clamscan", ...])` — slower, fork per file.
6. If none available, mark ClamAV `unavailable` and record that on every finding.

Startup health check (logged to the report header):
- clamd reachable? (`PING` → `PONG`)
- DB loaded? (`VERSION` returns engine + sig date)
- INSTREAM works? (send a tiny harmless buffer)
- `StreamMaxLength` known? Read from `clamd.conf`. If a candidate file exceeds it, fall back to `clamscan` for that file rather than truncating.

INSTREAM is preferred (no fork per file, in-memory DB reuse). Embedded payloads extracted in §4.5 are also INSTREAM-scanned.

### 4.8 IOC / hash workflow
- Local SHA-256 blocklist at `pdfscan/rules/ioc_hashes.txt` and `--ioc-hashes FILE`.
- Optional fuzzy hash matching (ssdeep, TLSH) when those libraries are installed; off by default.
- VirusTotal: **off by default**, two separate flags:
  - `--vt-hash-lookup` — submits only the SHA-256 (no file content).
  - `--vt-submit-file` — uploads the file. Requires explicit confirmation per run (or `vt_submit_file = true` in the config). Never the default.
- API keys read from `VT_API_KEY` env, never persisted.

### 4.9 Risk scoring & verdicts (`scoring.py`)
Six verdict states (no more "0–9 = clean" — that was dishonest):

| Verdict | Meaning |
|---|---|
| `no_findings` | every layer ran successfully and reported nothing |
| `low` | minor signals only (e.g. `/AcroForm` with no JS) |
| `suspicious` | combination rules or YARA medium hit |
| `high` | multiple combination rules, or YARA high hit |
| `critical` | ClamAV hit, or embedded-file hit, or `/Launch` + payload |
| `unknown` | could not scan with confidence (see below) |

`unknown` is a first-class state, applied when:
- encrypted PDF without password
- parser timeout (process killed)
- parser crash / `pikepdf` raises
- file > `--max-size`
- ClamAV required but unavailable (when `--require-clamav`)
- read permission denied / file disappeared mid-scan
- decompression bomb hit rlimit
- YARA rules failed to load and `--require-yara` was set

`unknown` files are **not** reported as clean and **not** quarantined automatically.

Indicator weights (combination-aware):

| Indicator | Weight |
|---|---|
| ClamAV hit (file or embedded) | +100 (auto-CRITICAL) |
| YARA high-severity hit | +60 |
| YARA medium hit | +25 |
| `/Launch` present | +40 |
| `/Launch` + `/EmbeddedFile` | +50 (combo) |
| `/JS` or `/JavaScript` + suspicious token | +30 |
| `/OpenAction` + JS | +20 (combo) |
| `/AA` + JS | +20 (combo) |
| `/EmbeddedFile` (any) | +15 |
| `/EmbeddedFile` flagged by ClamAV | +80 |
| Polyglot header offset | +25 |
| Multiple `%%EOF` + JS | +15 (combo) |
| Broken xref | +10 |
| URI on blocklist | +30 |
| `/AcroForm` + `/XFA` | +15 (combo) |
| `/RichMedia` or `/Flash` | +20 |
| Heap-spray-shaped JS | +30 |
| Filter chain depth > 3 | +10 |
| SHA-256 on local IOC list | +100 (auto-CRITICAL) |

Score → verdict map: `<10 low/no_findings`, `10–29 low`, `30–59 suspicious`, `60–99 high`, `≥100 critical`.

---

## 5. Process Model & Killable Timeouts

`Future.timeout()` does **not** kill native C code that is hung inside `pikepdf`/qpdf, YARA, or ClamAV decompression. Cooperative cancellation is not enough.

Design (`workers.py`):
- `multiprocessing.Pool` is **not** used directly. Instead a custom pool keeps a list of child processes, each pinned to one task at a time.
- Parent dispatches `(file_path, options)` to an idle child via a `Queue`.
- Parent starts a wall-clock timer per dispatch (default 30 s, configurable).
- On timeout: parent calls `child.terminate()`, then `join(2)`, then `child.kill()` if still alive. Replacement child is spawned. The file is recorded with verdict `unknown_timeout`.
- Workers are recycled after `--worker-recycle N` files (default 200) to bound memory growth from leaky C extensions.
- Each worker sets `resource.setrlimit(RLIMIT_AS, …)` (default 1 GB) and `RLIMIT_CPU` (default 60 s) on startup.
- Each worker registers a `SIGTERM` handler that flushes its evidence buffer to disk before exiting (best effort).

---

## 6. Privilege Model

Default: run as the invoking user; scan only paths that user can read.

Root mode (opt-in only):
- `--as-root` or `--full-system` required to walk the whole filesystem.
- Even then, the **parent** (which discovers files and opens them read-only) is the only process that needs root.
- Workers are spawned as a low-privilege user (created at install time as `pdfscan`, or specified via `--worker-user`) using `os.setresuid` / `os.setresgid` / `os.setgroups` after `fork`. Workers do all parsing, YARA, ClamAV stream calls, and evidence writes.
- The parent passes file content to the worker by **already-opened read-only file descriptor** where possible (so the worker never needs filesystem permissions on the original path).
- Sockets to clamd are opened by the parent and either passed via `socket.fromfd` to the worker or proxied.

This way a hostile PDF that triggers an RCE in `pikepdf` or libqpdf still cannot read `/root/.ssh/` or write outside the report directory.

---

## 7. Filesystem Safety

- Only regular files (`stat.S_ISREG`). Skip FIFOs, sockets, character/block devices.
- `--one-file-system` default on.
- Symlink-loop guard via visited `(dev, inode)` set.
- Hardlink dedupe via the same set.
- I/O errors, race-condition disappearance, and permission denials become `unknown_io_error` findings, not crashes.
- The scanner never writes inside scanned directories. All output goes to `--out-dir`.
- Bind-mount awareness: enforced by `--one-file-system`.

---

## 8. Quarantine

Three modes via `--quarantine-mode`:

| Mode | Behavior |
|---|---|
| `none` | **default**. No copies made. |
| `copy` | Copy suspicious/high/critical files to `quarantine/files/<sha256>.pdf`, mode `0400`. |
| `hardlink` | Same name scheme, but a hardlink. Same filesystem only. Faster, no extra disk. |

Rules:
- **Stored filename is always `<sha256>.pdf`.** Original filenames may contain Unicode RTL overrides, terminal escape sequences, path tricks, or misleading double extensions. Do not preserve them in the storage path.
- Original metadata (path, name, mtime, uid/gid/mode, score, reasons) goes in `quarantine/manifest.jsonl` only.
- Mode `0400`, owned by the worker user, on a `noexec` tmpfs when available (`/dev/shm/pdfscan-$$` or similar).
- Files are **never moved** and **never deleted** by the scanner.
- The same scheme applies to extracted embedded payloads under `quarantine/files/<sha256>.bin`.

Manifest entry:
```json
{
  "sha256": "...",
  "original_path": "/home/x/Downloads/invoice.pdf",
  "stored_path": "quarantine/files/<sha256>.pdf",
  "score": 80,
  "verdict": "high",
  "reasons": ["yara:Maldoc_PDF_OpenAction_JS", "openaction+js"],
  "stored_at": "2026-04-25T11:30:00Z"
}
```

---

## 9. Evidence Store

Per-file evidence is **not** embedded in the Markdown report (a report containing live JS or shellcode is itself a hazard). It lives on disk and is referenced by path:

```
evidence/<sha256>/
  javascript_001.txt
  javascript_002.txt
  uri_list.txt
  embedded_files.jsonl
  raw_token_counts.json
  pikepdf_walk.json
  yara_matches.json
  clamav.json
```

The Markdown report shows only short snippets (≤ 200 chars), reasons, and paths into `evidence/`.

---

## 10. Output / Reporting

Artifacts in `--out-dir` (default `./pdfscan-report-YYYYMMDD-HHMMSS/`):

1. `findings.jsonl` — one line per file, **streamed and flushed** as each file completes.
2. `summary.csv` — `path, sha256, verdict, score, top_reason`.
3. `report.md` — grouped by verdict, top-N expanded, references into `evidence/`.
4. `quarantine/files/` + `quarantine/manifest.jsonl` (when enabled).
5. `evidence/<sha256>/...` (when deep scan ran).
6. `compiled_rules.yarc` — the compiled YARA bundle used for this run.
7. `run.json` — scanner version, rules version, ClamAV engine + DB date, host, start/finish, total counts per verdict.

Per-file JSONL record:
```json
{
  "scanner_version": "0.1.0",
  "rules_version": "2026-04-20",
  "clamav_version": "1.4.1/27412/2026-04-25",
  "host": "kali",
  "scan_started": "2026-04-25T11:30:00Z",
  "scan_finished": "2026-04-25T11:30:01Z",
  "path": "/home/x/Downloads/invoice.pdf",
  "realpath": "/home/x/Downloads/invoice.pdf",
  "inode": 123456,
  "device": 64513,
  "uid": 1000,
  "gid": 1000,
  "mode": "0644",
  "mtime": "2026-04-20T08:14:00Z",
  "size": 184320,
  "sha256": "…",
  "ssdeep": null,
  "tlsh": null,
  "pdf_header_offset": 0,
  "encrypted": false,
  "parser_status": "ok",
  "tag_counts": { "/JS": 1, "/JavaScript": 1, "/OpenAction": 1, "/EmbeddedFile": 0 },
  "yara_matches": ["Maldoc_PDF_OpenAction_JS"],
  "clamav": { "status": "ok", "signature": null },
  "uri_count": 2,
  "embedded_count": 0,
  "score": 70,
  "verdict": "high",
  "reasons": ["yara:Maldoc_PDF_OpenAction_JS", "openaction+js", "heap_spray_pattern"],
  "evidence_dir": "evidence/<sha256>/",
  "timing_ms": {
    "hash": 8,
    "lex": 12,
    "yara_raw": 5,
    "pikepdf": 90,
    "extract_js": 14,
    "yara_js": 3,
    "clamav": 35,
    "total": 167
  }
}
```

Exit codes: `0` no findings ≥ suspicious, `2` suspicious, `3` high/critical, `4` only `unknown` results, `1` scanner error.

---

## 11. Configuration

CLI args override config file. Lookup order (first wins):
1. `--config FILE`
2. `./pdfscan.toml`
3. `~/.config/pdfscan/config.toml`
4. `/etc/pdfscan/config.toml`

`pdfscan.toml.example`:
```toml
roots = ["/home", "/root", "/tmp", "/var/tmp", "/opt", "/srv"]
exclude = ["/proc", "/sys", "/dev", "/run", "/var/lib/docker",
           "/var/lib/containers", "/.snapshots"]
exclude_regex = ['/node_modules/', '/\\.git/']
one_file_system = true
follow_symlinks = false
max_size = "256M"
max_depth = 64
jobs = 8
timeout = 30
worker_recycle = 200
worker_memory_mb = 1024

[clamav]
enabled = true
required = false
socket = "auto"        # auto | /path/to/clamd.ctl | tcp://host:port

[yara]
enabled = true
required = false
extra_rule_dirs = []

[ioc]
hash_file = "pdfscan/rules/ioc_hashes.txt"
fuzzy = false
vt_hash_lookup = false
vt_submit_file = false

[quarantine]
mode = "none"          # none | copy | hardlink

[report]
formats = ["jsonl", "csv", "md"]
min_score = 10
```

---

## 12. CLI Surface

```
scan.py [PATHS...]
  --config FILE
  --out-dir DIR
  --jobs N
  --max-size BYTES
  --max-depth N
  --timeout SECONDS
  --worker-recycle N
  --worker-memory-mb N
  --one-file-system / --no-one-file-system
  --follow-symlinks
  --include DIR        (repeatable)
  --exclude DIR        (repeatable)
  --exclude-regex RE
  --as-root / --full-system
  --worker-user NAME
  --no-clamav
  --require-clamav
  --no-yara
  --require-yara
  --rules DIR          (repeatable)
  --ioc-hashes FILE
  --vt-hash-lookup
  --vt-submit-file
  --quarantine-mode none|copy|hardlink
  --full               (skip cheap-triage gate; deep-scan every file)
  --min-score N
  --format jsonl,csv,md
  --quiet | --verbose
  --dry-run
```

---

## 13. Performance Targets

- Discovery + hashing for ~50k files on a typical Kali laptop SSD: < 2 min.
- 8 workers, mixed real-world directory: ~150–400 PDFs/sec for files that exit at cheap triage; ~20/sec when ClamAV INSTREAM dominates.
- Memory: < 200 MB per worker steady-state, capped by rlimit at 1 GB.
- Cache hits on a re-scan: near-free (sqlite lookup only).

---

## 14. Implementation Phases

| Phase | Deliverable | Effort |
|---|---|---|
| 0 | Repo scaffold, `pyproject.toml`, lint/CI | 0.5 d |
| 1 | `discover.py`, `hashing.py`, JSONL streaming reporter | 1 d |
| 2 | `lex.py` raw scanner with `/#xx` normalization, `pdfid_lite`, `structure.py`, scoring v1 | 1.5 d |
| 3 | `workers.py` killable process pool, rlimits, recycle | 1 d |
| 4 | `extractors.py` (pikepdf JS/EmbeddedFile/URI), evidence store | 1.5 d |
| 5 | `yara_engine.py` with .yarc save/load, per-worker init | 0.75 d |
| 6 | `clamav_client.py` socket discovery, INSTREAM, health check, fallback | 1 d |
| 7 | Privilege separation (worker user, fd passing) | 1 d |
| 8 | Quarantine, evidence layout, CSV/Markdown report, exit codes | 0.5 d |
| 9 | Config file loader, sqlite cache | 0.5 d |
| 10 | Test corpus + pytest suite (acceptance criteria below) | 1.5 d |
| 11 | `install.sh`, `scan.sh`, optional systemd timer | 0.5 d |

**Total: ~11 days.**

---

## 15. Test Plan

Three sample tiers — none of them live malware:

```
tests/samples/
  benign/           # real, harmless PDFs (Kali docs)
  inert_suspicious/ # locally generated, contain markers but no working payload
  malformed/        # broken xref, multi-EOF, polyglot, truncated
```

Required test cases:
- normal benign PDF → `no_findings`
- encrypted PDF (no password) → `unknown_encrypted`
- malformed xref → handled, recorded, no crash
- multiple `%%EOF` markers
- polyglot prefix (junk before `%PDF-`)
- obfuscated `/Java#53cript` and `/J#53` → counted as `/JavaScript` / `/JS`
- inert embedded file → extracted, hashed, stored under sha256
- URI extraction
- file over `--max-size` → `unknown_too_large`
- worker timeout (sample with infinite-loop-shaped JS extraction harness) → `unknown_timeout`, worker terminated, replacement spawned
- unreadable file → `unknown_io_error`
- broken symlink
- ClamAV unavailable (mocked) → marked unavailable in report header, every record carries `clamav.status="unavailable"`
- YARA rules dir empty → handled with `--no-yara` semantics
- corrupt YARA rule file → that rule skipped, others compile
- duplicate file (same sha256) at two paths → reported twice, deep-scan results cached
- hardlink to same inode → reported once

CI runs against `benign/` and `inert_suspicious/` only. `malformed/` is generated by a small builder in `tests/samples/build.py`.

---

## 16. v1 Acceptance Criteria

Before tagging v1:

- [ ] Scans a directory recursively without modifying any scanned file.
- [ ] Handles unreadable / disappearing / non-regular files without crashing.
- [ ] Detects basic active-content indicators (`/JS`, `/OpenAction`, `/Launch`, `/EmbeddedFile`, `/AA`, `/URI`).
- [ ] Detects obfuscated PDF names (`/J#53`, `/Java#53cript`, `/Open#41ction`).
- [ ] Runs YARA safely under multiprocessing via compiled `.yarc` + per-worker load — no pickling of `yara.Rules`.
- [ ] Runs without ClamAV but reports it as unavailable in every record and the run header.
- [ ] Process-level timeout actually kills stuck workers (verified by test harness).
- [ ] Produces valid JSONL even after a partial / mid-scan crash (streamed line-buffered writes).
- [ ] Never executes extracted JavaScript or embedded files.
- [ ] Never uploads files or hashes to any network service unless explicitly enabled.
- [ ] Has an `unknown` verdict and uses it honestly.
- [ ] Quarantine stores by sha256, never by original filename.
- [ ] Default `--quarantine-mode` is `none`.
- [ ] Config file + CLI override both work and are documented.

---

## 17. Risks & Limitations

- **Encrypted PDFs** — content opaque without a password. Recorded as `unknown_encrypted`, with hash + ClamAV + YARA-on-raw still applied.
- **0-day exploits** — by definition not in ClamAV/YARA. Heuristic + structural layers are the only defense; flagged `suspicious` rather than `critical`.
- **JBIG2 / decompression bombs** — mitigated by per-worker `RLIMIT_AS` and per-file timeout, not eliminated.
- **False positives** — many legitimate PDFs use `/AcroForm` and `/JS` for validation. Combination-rule scoring keeps these at low/medium, never critical without corroboration.
- **Signature freshness** — ClamAV and YARA decay fast. `install.sh` schedules `freshclam` and a weekly Git pull of the rules bundle.
- **Trust boundary** — even with privilege separation, a kernel-level exploit in libqpdf could still be dangerous. Run scans on hardened / disposable VMs when sweeping untrusted corpora.

---

## 18. Out of Scope (v1)

- Sandboxed dynamic execution of extracted JS (would need a JS engine in a seccomp jail — v2).
- VirusTotal / Hybrid Analysis submission by default.
- GUI; CLI + reports only.
- Real-time inotify watching (v1 is on-demand or cron).

---

## 19. Open Questions for the User

1. Default scan roots: home-focused (`/home /root /tmp /var/tmp /opt /srv /media /mnt`) or full-system (`/` with `--full-system` required)?
2. Should `--require-clamav` be the default on Kali, given clamav-daemon ships with the distro?
3. Worker user: create a dedicated `pdfscan` system user at install time, or reuse `nobody`?
4. Systemd timer for nightly scans wanted in v1, or leave to user?
5. Fuzzy hashing (ssdeep/TLSH) — include in default install, or optional extra?
