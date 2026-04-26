from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from .acceleration import shannon_entropy_gpu
from .lex import LexResult


STREAM_RE = re.compile(rb"<<(?P<dict>.*?)>>\s*stream\r?\n(?P<body>.*?)\r?\nendstream", re.S)


@dataclass(slots=True)
class StructureResult:
    reasons: list[str] = field(default_factory=list)
    score_hints: dict[str, int] = field(default_factory=dict)
    max_entropy: float = 0.0
    parser_status: str = "not_run"


def analyze(
    data: bytes,
    lex: LexResult,
    *,
    use_gpu_entropy: bool = False,
    min_gpu_entropy_size: int = 4 * 1024 * 1024,
) -> StructureResult:
    result = StructureResult()
    if lex.header_offset is None:
        result.reasons.append("missing_pdf_header")
        result.score_hints["missing_pdf_header"] = 20
    elif lex.header_offset > 0:
        result.reasons.append("polyglot_header_offset")
        result.score_hints["polyglot_header_offset"] = 25
    if lex.raw_counts.get("eof", 0) > 1 and lex.has_js:
        result.reasons.append("multiple_eof_with_js")
        result.score_hints["multiple_eof_with_js"] = 15
    if lex.raw_counts.get("obj") != lex.raw_counts.get("endobj"):
        result.reasons.append("obj_endobj_mismatch")
        result.score_hints["obj_endobj_mismatch"] = 10
    if lex.raw_counts.get("xref", 0) == 0:
        result.reasons.append("xref_missing")
        result.score_hints["xref_missing"] = 10
    if lex.max_filter_chain_depth > 3:
        result.reasons.append("filter_chain_depth_gt_3")
        result.score_hints["filter_chain_depth_gt_3"] = 10
    result.max_entropy = max_stream_entropy(
        data,
        use_gpu_entropy=use_gpu_entropy,
        min_gpu_entropy_size=min_gpu_entropy_size,
    )
    if result.max_entropy >= 7.5:
        result.reasons.append("high_stream_entropy")
        result.score_hints["high_stream_entropy"] = 10
    return result


def max_stream_entropy(
    data: bytes,
    *,
    use_gpu_entropy: bool = False,
    min_gpu_entropy_size: int = 4 * 1024 * 1024,
) -> float:
    maximum = 0.0
    for match in STREAM_RE.finditer(data):
        dictionary = match.group("dict")
        if b"/Subtype" in dictionary and any(
            subtype in dictionary for subtype in (b"/Image", b"/JPXDecode")
        ):
            continue
        body = match.group("body")
        if len(body) < 128:
            continue
        maximum = max(
            maximum,
            shannon_entropy(body, use_gpu=use_gpu_entropy, min_gpu_size=min_gpu_entropy_size),
        )
    return maximum


def shannon_entropy(
    data: bytes,
    *,
    use_gpu: bool = False,
    min_gpu_size: int = 4 * 1024 * 1024,
) -> float:
    if not data:
        return 0.0
    if use_gpu and len(data) >= min_gpu_size:
        accelerated = shannon_entropy_gpu(data)
        if accelerated is not None:
            return accelerated
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts if count)
