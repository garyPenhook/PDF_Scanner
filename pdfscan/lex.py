from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path


NAME_RE = re.compile(rb"/(?:#[0-9A-Fa-f]{2}|[^\s<>\[\]\(\)\{\}/%#]+)+")
FILTER_RE = re.compile(rb"/Filter\s*(?:\[(?P<array>[^\]]+)\]|(?P<single>/[A-Za-z0-9#]+))", re.S)

INTERESTING_NAMES = [
    "/JS",
    "/JavaScript",
    "/AA",
    "/OpenAction",
    "/Launch",
    "/SubmitForm",
    "/ImportData",
    "/GoToR",
    "/GoToE",
    "/Named",
    "/URI",
    "/Sound",
    "/Movie",
    "/Rendition",
    "/3D",
    "/RichMedia",
    "/Flash",
    "/XFA",
    "/AcroForm",
    "/NeedAppearances",
    "/EmbeddedFile",
    "/ObjStm",
    "/FlateDecode",
    "/ASCIIHexDecode",
    "/ASCII85Decode",
    "/LZWDecode",
    "/JBIG2Decode",
]


@dataclass(slots=True)
class LexResult:
    header_offset: int | None
    tag_counts: dict[str, int] = field(default_factory=dict)
    raw_counts: dict[str, int] = field(default_factory=dict)
    max_filter_chain_depth: int = 0
    names_seen: list[str] = field(default_factory=list)

    @property
    def has_js(self) -> bool:
        return self.tag_counts.get("/JS", 0) > 0 or self.tag_counts.get("/JavaScript", 0) > 0


def normalize_pdf_name(name: bytes) -> str:
    out = bytearray()
    index = 0
    while index < len(name):
        byte = name[index]
        if byte == 0x23 and index + 2 < len(name):
            token = name[index + 1 : index + 3]
            try:
                out.append(int(token.decode("ascii"), 16))
                index += 3
                continue
            except ValueError:
                pass
        out.append(byte)
        index += 1
    return out.decode("latin-1", errors="replace")


def scan_bytes(data: bytes) -> LexResult:
    header_offset = data.find(b"%PDF-")
    if header_offset < 0:
        header_offset = None
    raw_counts = {
        "eof": data.count(b"%%EOF"),
        "obj": len(re.findall(rb"(?<!end)\bobj\b", data)),
        "endobj": data.count(b"endobj"),
        "stream": len(re.findall(rb"(?<!end)\bstream\b", data)),
        "endstream": data.count(b"endstream"),
        "xref": len(re.findall(rb"\bxref\b", data)),
        "trailer": len(re.findall(rb"\btrailer\b", data)),
    }
    tag_counts = {name: 0 for name in INTERESTING_NAMES}
    names_seen: list[str] = []
    for match in NAME_RE.finditer(data):
        normalized = normalize_pdf_name(match.group(0))
        names_seen.append(normalized)
        if normalized in tag_counts:
            tag_counts[normalized] += 1
    return LexResult(
        header_offset=header_offset,
        tag_counts=tag_counts,
        raw_counts=raw_counts,
        max_filter_chain_depth=_max_filter_chain_depth(data),
        names_seen=names_seen[:1000],
    )


def scan_file(path: Path, max_read: int | None = None) -> LexResult:
    if max_read is None:
        data = path.read_bytes()
    else:
        with path.open("rb") as fh:
            data = fh.read(max_read)
    return scan_bytes(data)


def write_token_counts(path: Path, result: LexResult) -> None:
    payload = {
        "header_offset": result.header_offset,
        "tag_counts": result.tag_counts,
        "raw_counts": result.raw_counts,
        "max_filter_chain_depth": result.max_filter_chain_depth,
        "sample_names_seen": result.names_seen[:250],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _max_filter_chain_depth(data: bytes) -> int:
    max_depth = 0
    for match in FILTER_RE.finditer(data):
        value = match.group("array") or match.group("single") or b""
        depth = len(NAME_RE.findall(value))
        max_depth = max(max_depth, depth)
    return max_depth
