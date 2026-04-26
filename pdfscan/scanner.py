from __future__ import annotations

import atexit
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, Future, ProcessPoolExecutor, wait
import multiprocessing as mp
from pathlib import Path
import platform
import time
from typing import Any, Iterable, Iterator

from . import RULES_VERSION, __version__
from .acceleration import AccelerationStatus, detect_acceleration
from .cache import ScanCache
from .clamav_client import ClamAVClient
from .config import AppConfig
from .discover import discover
from .evidence import EvidenceStore
from .extractors import deep_extract, raw_extract
from .hashing import sha256_file
from .ioc import load_hashes
from .lex import scan_bytes, write_token_counts
from .models import FileRecord, ScanContext, ScanFinding
from .quarantine import Quarantine
from .report import JsonlWriter, write_markdown, write_run_json, write_summary_csv
from .scoring import score_indicators
from .structure import analyze
from .util import ensure_private_dir, iso_from_timestamp, utc_now
from .workers import run_with_timeout
from .yara_engine import YaraEngine


_WORKER_CONTEXT: ScanContext | None = None
_WORKER_CONFIG: AppConfig | None = None
_WORKER_CLAMAV: ClamAVClient | None = None
_WORKER_YARA: YaraEngine | None = None
_WORKER_IOC_HASHES: set[str] | None = None
_WORKER_CACHE: ScanCache | None = None
_WORKER_QUARANTINE: Quarantine | None = None
_WORKER_ACCELERATION: AccelerationStatus | None = None


def run_scan(config: AppConfig) -> int:
    config.jobs = max(1, config.jobs)
    started = utc_now()
    out_dir = config.out_dir or Path(f"pdfscan-report-{time.strftime('%Y%m%d-%H%M%S')}")
    out_dir = out_dir.expanduser().resolve()
    ensure_private_dir(out_dir)
    ensure_private_dir(out_dir / "evidence")
    ensure_private_dir(out_dir / "quarantine")
    clamav = ClamAVClient.discover(config.clamav.socket, enabled=config.clamav.enabled)
    rule_dirs = [Path(__file__).parent / "rules", *config.yara.extra_rule_dirs]
    compiled_rules_path = out_dir / "compiled_rules.yarc"
    yara_engine = YaraEngine.build(
        rule_dirs,
        compiled_rules_path,
        enabled=config.yara.enabled,
        required=config.yara.required,
    )
    ioc_hashes = load_hashes(config.ioc.hash_files)
    acceleration = detect_acceleration(config.acceleration.gpu, config.jobs)
    context = ScanContext(
        out_dir=out_dir,
        evidence_dir=out_dir / "evidence",
        quarantine_dir=out_dir / "quarantine",
        scan_started=started,
        host=platform.node(),
        scanner_version=__version__,
        rules_version=RULES_VERSION,
        clamav_version=clamav.status.version,
    )
    jsonl = JsonlWriter(out_dir / "findings.jsonl")
    quarantine_mode = "none" if config.dry_run else config.quarantine_mode
    cache: ScanCache | None = None
    findings: list[ScanFinding] = []
    try:
        if config.jobs == 1:
            cache = ScanCache(Path.home() / ".cache/pdfscan/seen.db", enabled=not config.dry_run)
            quarantine = Quarantine(out_dir / "quarantine", quarantine_mode)
            scan_results = (
                _scan_record(
                    record.path,
                    context,
                    config,
                    clamav,
                    yara_engine,
                    ioc_hashes,
                    cache,
                    quarantine,
                    acceleration,
                )
                for record in discover(config)
            )
        else:
            scan_results = _scan_records_parallel(
                discover(config),
                context,
                config,
                yara_engine,
                compiled_rules_path,
                ioc_hashes,
                acceleration,
                quarantine_mode,
            )
        for finding in scan_results:
            findings.append(finding)
            jsonl.write(finding)
            if config.verbose and not config.quiet:
                print(f"{finding.verdict:11} {finding.score:3} {finding.path}")
    finally:
        jsonl.close()
        if cache is not None:
            cache.close()
    finished = utc_now()
    run_info = {
        "scanner_version": __version__,
        "rules_version": RULES_VERSION,
        "started": started,
        "finished": finished,
        "host": context.host,
        "out_dir": out_dir.as_posix(),
        "clamav_status": clamav.status.status,
        "clamav_version": clamav.status.version,
        "yara_status": yara_engine.status,
        "acceleration": acceleration.to_json(),
        "total": len(findings),
        "counts": dict(Counter(f.verdict for f in findings)),
    }
    if "csv" in config.report.formats:
        write_summary_csv(out_dir / "summary.csv", findings)
    if "md" in config.report.formats:
        write_markdown(out_dir / "report.md", findings, run_info)
    write_run_json(out_dir / "run.json", run_info)
    if not config.quiet:
        print(f"Report written to {out_dir}")
    return _exit_code(findings)


def _scan_records_parallel(
    records: Iterable[FileRecord],
    context: ScanContext,
    config: AppConfig,
    yara_engine: YaraEngine,
    compiled_rules_path: Path,
    ioc_hashes: set[str],
    acceleration: AccelerationStatus,
    quarantine_mode: str,
) -> Iterator[ScanFinding]:
    mp_context = mp.get_context("spawn")
    pool_options: dict[str, Any] = {
        "max_workers": config.jobs,
        "mp_context": mp_context,
        "initializer": _init_scan_worker,
        "initargs": (
            config,
            context,
            compiled_rules_path.as_posix() if yara_engine.status == "ok" else None,
            yara_engine.status,
            ioc_hashes,
            acceleration,
            quarantine_mode,
        ),
    }
    if config.worker_recycle > 0:
        pool_options["max_tasks_per_child"] = config.worker_recycle
    with ProcessPoolExecutor(**pool_options) as executor:
        futures: dict[Future[ScanFinding], Path] = {}
        pending_limit = max(config.jobs, config.jobs * 2)
        for record in records:
            futures[executor.submit(_scan_record_worker, record.path.as_posix())] = record.path
            if len(futures) >= pending_limit:
                yield from _completed_futures(futures, context)
        while futures:
            yield from _completed_futures(futures, context)


def _completed_futures(
    futures: dict[Future[ScanFinding], Path],
    context: ScanContext,
) -> Iterator[ScanFinding]:
    done, _ = wait(futures, return_when=FIRST_COMPLETED)
    for future in done:
        path = futures.pop(future)
        try:
            yield future.result()
        except Exception as exc:
            yield _unknown_worker_error(path, context, str(exc))


def _init_scan_worker(
    config: AppConfig,
    context: ScanContext,
    compiled_rules_path: str | None,
    yara_status: str,
    ioc_hashes: set[str],
    acceleration: AccelerationStatus,
    quarantine_mode: str,
) -> None:
    global _WORKER_ACCELERATION
    global _WORKER_CACHE
    global _WORKER_CLAMAV
    global _WORKER_CONFIG
    global _WORKER_CONTEXT
    global _WORKER_IOC_HASHES
    global _WORKER_QUARANTINE
    global _WORKER_YARA

    _WORKER_CONTEXT = context
    _WORKER_CONFIG = config
    _WORKER_CLAMAV = ClamAVClient.discover(config.clamav.socket, enabled=config.clamav.enabled)
    if compiled_rules_path is not None:
        _WORKER_YARA = YaraEngine.load_compiled(
            Path(compiled_rules_path),
            enabled=config.yara.enabled,
            required=config.yara.required,
        )
    else:
        _WORKER_YARA = YaraEngine(enabled=False, status=yara_status)
    _WORKER_IOC_HASHES = ioc_hashes
    _WORKER_CACHE = ScanCache(Path.home() / ".cache/pdfscan/seen.db", enabled=not config.dry_run)
    _WORKER_QUARANTINE = Quarantine(context.quarantine_dir, quarantine_mode)
    _WORKER_ACCELERATION = acceleration
    atexit.register(_close_scan_worker)


def _close_scan_worker() -> None:
    global _WORKER_CACHE
    if _WORKER_CACHE is not None:
        _WORKER_CACHE.close()
        _WORKER_CACHE = None


def _scan_record_worker(path_text: str) -> ScanFinding:
    if (
        _WORKER_CONTEXT is None
        or _WORKER_CONFIG is None
        or _WORKER_CLAMAV is None
        or _WORKER_YARA is None
        or _WORKER_IOC_HASHES is None
        or _WORKER_CACHE is None
        or _WORKER_QUARANTINE is None
    ):
        raise RuntimeError("scan worker was not initialized")
    return _scan_record(
        Path(path_text),
        _WORKER_CONTEXT,
        _WORKER_CONFIG,
        _WORKER_CLAMAV,
        _WORKER_YARA,
        _WORKER_IOC_HASHES,
        _WORKER_CACHE,
        _WORKER_QUARANTINE,
        _WORKER_ACCELERATION,
    )


def _scan_record(
    path: Path,
    context: ScanContext,
    config: AppConfig,
    clamav: ClamAVClient,
    yara_engine: YaraEngine,
    ioc_hashes: set[str],
    cache: ScanCache,
    quarantine: Quarantine,
    acceleration: AccelerationStatus | None = None,
) -> ScanFinding:
    started = utc_now()
    t0 = time.perf_counter()
    try:
        st = path.stat()
    except OSError as exc:
        return _unknown_io(path, context, started, str(exc))
    finding = ScanFinding(
        path=path.as_posix(),
        realpath=path.resolve(strict=False).as_posix(),
        inode=st.st_ino,
        device=st.st_dev,
        uid=st.st_uid,
        gid=st.st_gid,
        mode=f"{st.st_mode & 0o7777:04o}",
        mtime=iso_from_timestamp(st.st_mtime),
        size=st.st_size,
        scan_started=started,
        scanner_version=context.scanner_version,
        rules_version=context.rules_version,
        clamav_version=context.clamav_version,
        host=context.host,
    )
    if st.st_size > config.max_size:
        finding.verdict = "unknown"
        finding.reasons = ["unknown_too_large"]
        finding.error = f"file exceeds max size {config.max_size}"
        finding.scan_finished = utc_now()
        return finding
    try:
        hash_start = time.perf_counter()
        digest = sha256_file(path)
        finding.sha256 = digest
        finding.timing_ms["hash"] = _elapsed_ms(hash_start)
        cached = cache.get(
            digest,
            context.scanner_version,
            context.rules_version,
            context.clamav_version or clamav.status.status,
        )
        if cached:
            _apply_cached(finding, cached)
            finding.path = path.as_posix()
            finding.realpath = path.resolve(strict=False).as_posix()
            finding.scan_finished = utc_now()
            return finding
        data = path.read_bytes()
    except OSError as exc:
        return _unknown_io(path, context, started, str(exc))

    lex_start = time.perf_counter()
    lex = scan_bytes(data)
    finding.timing_ms["lex"] = _elapsed_ms(lex_start)
    finding.pdf_header_offset = lex.header_offset
    finding.tag_counts = {key: value for key, value in lex.tag_counts.items() if value}
    evidence_needed = config.full or _triage_interesting(finding.tag_counts, lex, data)
    evidence = EvidenceStore(context.evidence_dir, finding.sha256)
    finding.evidence_dir = evidence.relative_to(context.out_dir)
    write_token_counts(evidence.root / "raw_token_counts.json", lex)

    structure_start = time.perf_counter()
    structure = analyze(
        data,
        lex,
        use_gpu_entropy=acceleration is not None and acceleration.entropy_backend == "cuda",
        min_gpu_entropy_size=config.acceleration.min_gpu_entropy_size,
    )
    finding.timing_ms["structure"] = _elapsed_ms(structure_start)
    yara_matches: list[str] = []
    if yara_engine.enabled:
        yara_start = time.perf_counter()
        yara_matches.extend(yara_engine.match_file(path))
        finding.timing_ms["yara_raw"] = _elapsed_ms(yara_start)
    clam = (
        clamav.scan_file(path)
        if config.clamav.enabled
        else {"status": "disabled", "signature": None}
    )
    finding.clamav = clam

    extraction = raw_extract(data)
    if evidence_needed:
        status, payload = run_with_timeout(
            _deep_extract_worker,
            (
                path.as_posix(),
                context.out_dir.as_posix(),
                finding.sha256,
                "none" if config.dry_run else config.quarantine_mode,
                config.clamav.enabled,
            ),
            config.timeout,
        )
        if status == "timeout":
            finding.parser_status = "timeout_killed"
        elif status == "ok":
            extraction = _extraction_from_payload(payload)
            finding.parser_status = extraction.parser_status
            finding.encrypted = extraction.encrypted
        elif status == "error":
            finding.parser_status = "crash_error"
            finding.error = payload.get("error") if isinstance(payload, dict) else str(payload)
        else:
            finding.parser_status = f"crash_{status}"
            finding.error = str(payload)
    else:
        finding.parser_status = extraction.parser_status
    if yara_engine.enabled and extraction.javascript:
        yara_matches.extend(
            yara_engine.match_data(
                "\n".join(extraction.javascript).encode("latin-1", errors="ignore")
            )
        )
    finding.yara_matches = sorted(set(yara_matches))
    finding.uri_count = len(set(extraction.uris))
    finding.embedded_count = len(extraction.embedded)
    if extraction.uris:
        evidence.write_text("uri_list.txt", "\n".join(sorted(set(extraction.uris))) + "\n")
    score = score_indicators(
        tag_counts=finding.tag_counts,
        structure_reasons=structure.reasons,
        structure_hints=structure.score_hints,
        yara_matches=finding.yara_matches,
        clamav_signature=clam.get("signature"),
        ioc_hit=(finding.sha256 or "").lower() in ioc_hashes,
        js_suspicious=extraction.js_suspicious,
        uri_blocklist_hits=0,
        parser_status=finding.parser_status,
        encrypted=finding.encrypted,
        require_clamav_unavailable=config.clamav.required and clam.get("status") == "unavailable",
        error=finding.error,
    )
    finding.score = score.score
    finding.verdict = score.verdict
    finding.reasons = score.reasons
    if (
        not config.dry_run
        and config.quarantine_mode != "none"
        and finding.verdict in {"suspicious", "high", "critical"}
        and finding.sha256
    ):
        quarantine.store_pdf(
            path,
            finding.sha256,
            score=finding.score,
            verdict=finding.verdict,
            reasons=finding.reasons,
        )
    finding.timing_ms["total"] = _elapsed_ms(t0)
    finding.scan_finished = utc_now()
    cache.put(
        finding.sha256,
        context.scanner_version,
        context.rules_version,
        context.clamav_version or clamav.status.status,
        finding.to_json(),
    )
    return finding


def _deep_extract_worker(
    path_text: str,
    out_dir_text: str,
    sha256: str,
    quarantine_mode: str,
    clamav_enabled: bool,
) -> dict[str, Any]:
    path = Path(path_text)
    out_dir = Path(out_dir_text)
    evidence = EvidenceStore(out_dir / "evidence", sha256)
    quarantine = Quarantine(out_dir / "quarantine", quarantine_mode)
    clamav = ClamAVClient.discover(enabled=clamav_enabled)
    extraction = deep_extract(path, path.read_bytes(), evidence, quarantine, clamav)
    return {
        "parser_status": extraction.parser_status,
        "encrypted": extraction.encrypted,
        "javascript": extraction.javascript,
        "uris": extraction.uris,
        "embedded": extraction.embedded,
        "js_suspicious": extraction.js_suspicious,
        "errors": extraction.errors,
    }


def _extraction_from_payload(payload: dict[str, Any]):
    from .extractors import ExtractionResult

    return ExtractionResult(
        parser_status=payload.get("parser_status", "unknown"),
        encrypted=bool(payload.get("encrypted", False)),
        javascript=list(payload.get("javascript", [])),
        uris=list(payload.get("uris", [])),
        embedded=list(payload.get("embedded", [])),
        js_suspicious=bool(payload.get("js_suspicious", False)),
        errors=list(payload.get("errors", [])),
    )


def _triage_interesting(tag_counts: dict[str, int], lex, data: bytes) -> bool:
    active_names = (
        "/JS",
        "/JavaScript",
        "/OpenAction",
        "/AA",
        "/Launch",
        "/EmbeddedFile",
        "/URI",
    )
    if any(tag_counts.get(name, 0) for name in active_names):
        return True
    if lex.header_offset and lex.header_offset > 0:
        return True
    if lex.raw_counts.get("eof", 0) > 1:
        return True
    return b"/ObjStm" in data or b"/XFA" in data


def _unknown_worker_error(path: Path, context: ScanContext, error: str) -> ScanFinding:
    started = utc_now()
    return ScanFinding(
        path=path.as_posix(),
        realpath=path.resolve(strict=False).as_posix(),
        verdict="unknown",
        reasons=["unknown_worker_error"],
        error=error,
        scan_started=started,
        scan_finished=utc_now(),
        scanner_version=context.scanner_version,
        rules_version=context.rules_version,
        clamav_version=context.clamav_version,
        host=context.host,
    )


def _unknown_io(path: Path, context: ScanContext, started: str, error: str) -> ScanFinding:
    return ScanFinding(
        path=path.as_posix(),
        realpath=path.resolve(strict=False).as_posix(),
        verdict="unknown",
        reasons=["unknown_io_error"],
        error=error,
        scan_started=started,
        scan_finished=utc_now(),
        scanner_version=context.scanner_version,
        rules_version=context.rules_version,
        clamav_version=context.clamav_version,
        host=context.host,
    )


def _apply_cached(finding: ScanFinding, cached: dict[str, Any]) -> None:
    for key, value in cached.items():
        if hasattr(finding, key):
            setattr(finding, key, value)


def _elapsed_ms(start: float) -> int:
    return int((time.perf_counter() - start) * 1000)


def _exit_code(findings: list[ScanFinding]) -> int:
    verdicts = {finding.verdict for finding in findings}
    if "critical" in verdicts or "high" in verdicts:
        return 3
    if "suspicious" in verdicts:
        return 2
    if verdicts and verdicts <= {"unknown"}:
        return 4
    return 0
