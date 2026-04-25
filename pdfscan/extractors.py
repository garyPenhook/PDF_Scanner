from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .evidence import EvidenceStore
from .hashing import sha256_bytes
from .quarantine import Quarantine


URI_RE = re.compile(rb"/URI\s*(?:\((?P<paren>(?:\\.|[^\\)])*)\)|<(?P<hex>[0-9A-Fa-f\s]+)>)", re.S)
JS_RE = re.compile(
    rb"/(?:JS|JavaScript)\s*(?:\((?P<paren>(?:\\.|[^\\)]){0,200000})\)|<(?P<hex>[0-9A-Fa-f\s]{0,400000})>)",
    re.S,
)
SUSPICIOUS_JS_PATTERNS = [
    re.compile(pattern, re.I)
    for pattern in (
        rb"unescape\s*\(",
        rb"app\.alert",
        rb"util\.printf",
        rb"Collab\.collectEmailInfo",
        rb"getAnnots",
        rb"getIcon",
        rb"media\.newPlayer",
        rb"\beval\s*\(",
        rb"Function\s*\(",
        rb"String\.fromCharCode\s*\([^)]{80,}\)",
        rb"(?:%u[0-9A-Fa-f]{4}){20,}",
    )
]


@dataclass(slots=True)
class ExtractionResult:
    parser_status: str = "not_run"
    encrypted: bool = False
    javascript: list[str] = field(default_factory=list)
    uris: list[str] = field(default_factory=list)
    embedded: list[dict[str, Any]] = field(default_factory=list)
    js_suspicious: bool = False
    errors: list[str] = field(default_factory=list)


def raw_extract(data: bytes) -> ExtractionResult:
    result = ExtractionResult(parser_status="raw_only")
    result.javascript = [_decode_pdf_literal(match) for match in JS_RE.finditer(data)]
    result.uris = [_decode_pdf_literal(match) for match in URI_RE.finditer(data)]
    result.js_suspicious = javascript_suspicious("\n".join(result.javascript).encode("latin-1", errors="ignore"))
    return result


def deep_extract(
    path: Path,
    data: bytes,
    evidence: EvidenceStore,
    quarantine: Quarantine,
    clamav,
) -> ExtractionResult:
    result = raw_extract(data)
    result.parser_status = "ok"
    try:
        import pikepdf  # type: ignore
    except ImportError:
        result.parser_status = "pikepdf_unavailable_raw_only"
        _write_raw_evidence(result, evidence)
        return result
    try:
        with pikepdf.Pdf.open(path) as pdf:
            result.encrypted = bool(getattr(pdf, "is_encrypted", False))
            for index, obj in enumerate(pdf.objects):
                _walk_object(obj, result, evidence, quarantine, clamav, f"obj_{index}")
    except pikepdf.PasswordError:
        result.parser_status = "unknown_encrypted"
        result.encrypted = True
    except Exception as exc:
        result.parser_status = "parser_error"
        result.errors.append(str(exc))
    result.js_suspicious = result.js_suspicious or javascript_suspicious(
        "\n".join(result.javascript).encode("latin-1", errors="ignore")
    )
    _write_raw_evidence(result, evidence)
    return result


def javascript_suspicious(data: bytes) -> bool:
    if not data:
        return False
    if any(pattern.search(data) for pattern in SUSPICIOUS_JS_PATTERNS):
        return True
    if data.count(b"+") > 20 and len(data) > 1000:
        return True
    return False


def _write_raw_evidence(result: ExtractionResult, evidence: EvidenceStore) -> None:
    for index, script in enumerate(result.javascript, start=1):
        evidence.write_text(f"javascript_{index:03d}.txt", script)
    if result.uris:
        evidence.write_text("uri_list.txt", "\n".join(result.uris) + "\n")
    if result.embedded:
        for payload in result.embedded:
            evidence.append_jsonl("embedded_files.jsonl", payload)


def _walk_object(obj: Any, result: ExtractionResult, evidence: EvidenceStore, quarantine: Quarantine, clamav, label: str) -> None:
    try:
        import pikepdf  # type: ignore
    except ImportError:
        return
    if isinstance(obj, pikepdf.Dictionary):
        for key, value in obj.items():
            key_text = str(key)
            if key_text in ("/JS", "/JavaScript"):
                text = _pike_to_text(value)
                if text:
                    result.javascript.append(text)
            elif key_text == "/URI":
                text = _pike_to_text(value)
                if text:
                    result.uris.append(text)
            elif key_text == "/EmbeddedFile" and isinstance(value, pikepdf.Stream):
                _extract_embedded(value, result, evidence, quarantine, clamav, label)
            _walk_object(value, result, evidence, quarantine, clamav, label)
    elif isinstance(obj, pikepdf.Array):
        for value in obj:
            _walk_object(value, result, evidence, quarantine, clamav, label)


def _extract_embedded(stream: Any, result: ExtractionResult, evidence: EvidenceStore, quarantine: Quarantine, clamav, label: str) -> None:
    try:
        data = bytes(stream.read_bytes())
    except Exception as exc:
        result.errors.append(f"embedded_extract_error:{exc}")
        return
    digest = sha256_bytes(data)
    clam = clamav.scan_bytes(data) if clamav is not None else {"status": "not_run", "signature": None}
    stored = quarantine.store_payload(
        data,
        digest,
        {
            "source": label,
            "clamav": clam,
        },
    )
    metadata = {
        "sha256": digest,
        "size": len(data),
        "source": label,
        "stored_path": stored,
        "clamav": clam,
    }
    evidence.append_jsonl("embedded_files.jsonl", metadata)
    result.embedded.append(metadata)


def _pike_to_text(value: Any) -> str:
    try:
        if hasattr(value, "read_bytes"):
            return bytes(value.read_bytes()).decode("latin-1", errors="replace")
        return str(value)
    except Exception:
        return ""


def _decode_pdf_literal(match: re.Match[bytes]) -> str:
    raw = match.group("paren")
    if raw is not None:
        value = (
            raw.replace(rb"\(", b"(")
            .replace(rb"\)", b")")
            .replace(rb"\\", b"\\")
            .replace(rb"\n", b"\n")
            .replace(rb"\r", b"\r")
            .replace(rb"\t", b"\t")
        )
        return value.decode("latin-1", errors="replace")
    raw_hex = match.group("hex") or b""
    try:
        compact = re.sub(rb"\s+", b"", raw_hex)
        if len(compact) % 2:
            compact += b"0"
        return bytes.fromhex(compact.decode("ascii")).decode("latin-1", errors="replace")
    except ValueError:
        return raw_hex.decode("latin-1", errors="replace")
