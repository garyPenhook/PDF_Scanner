from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class ScoreResult:
    score: int = 0
    verdict: str = "no_findings"
    reasons: list[str] = field(default_factory=list)


def score_indicators(
    *,
    tag_counts: dict[str, int],
    structure_reasons: list[str],
    structure_hints: dict[str, int],
    yara_matches: list[str],
    clamav_signature: str | None,
    ioc_hit: bool,
    js_suspicious: bool,
    uri_blocklist_hits: int,
    parser_status: str,
    encrypted: bool,
    require_clamav_unavailable: bool = False,
    error: str | None = None,
) -> ScoreResult:
    if error:
        return ScoreResult(0, "unknown", [error])
    if encrypted:
        return ScoreResult(0, "unknown", ["unknown_encrypted"])
    if parser_status.startswith("timeout") or parser_status.startswith("crash"):
        return ScoreResult(0, "unknown", [parser_status])
    if require_clamav_unavailable:
        return ScoreResult(0, "unknown", ["clamav_required_unavailable"])

    score = 0
    reasons: list[str] = []
    if clamav_signature:
        score += 100
        reasons.append(f"clamav:{clamav_signature}")
    if ioc_hit:
        score += 100
        reasons.append("ioc_sha256")
    for match in yara_matches:
        lowered = match.lower()
        if "high" in lowered or "critical" in lowered:
            score += 60
        else:
            score += 25
        reasons.append(f"yara:{match}")
    if tag_counts.get("/Launch", 0):
        score += 40
        reasons.append("launch_action")
    if tag_counts.get("/Launch", 0) and tag_counts.get("/EmbeddedFile", 0):
        score += 50
        reasons.append("launch+embeddedfile")
    if (tag_counts.get("/JS", 0) or tag_counts.get("/JavaScript", 0)) and js_suspicious:
        score += 30
        reasons.append("javascript_suspicious_token")
    if tag_counts.get("/OpenAction", 0) and (tag_counts.get("/JS", 0) or tag_counts.get("/JavaScript", 0)):
        score += 20
        reasons.append("openaction+js")
    if tag_counts.get("/AA", 0) and (tag_counts.get("/JS", 0) or tag_counts.get("/JavaScript", 0)):
        score += 20
        reasons.append("aa+js")
    if tag_counts.get("/EmbeddedFile", 0):
        score += 15
        reasons.append("embeddedfile")
    if tag_counts.get("/AcroForm", 0) and tag_counts.get("/XFA", 0):
        score += 15
        reasons.append("acroform+xfa")
    if tag_counts.get("/RichMedia", 0) or tag_counts.get("/Flash", 0):
        score += 20
        reasons.append("richmedia_or_flash")
    if uri_blocklist_hits:
        score += 30
        reasons.append("uri_blocklist")
    for reason in structure_reasons:
        weight = structure_hints.get(reason, 0)
        if weight:
            score += weight
            reasons.append(reason)
    if not reasons and any(tag_counts.get(name, 0) for name in ("/AcroForm", "/URI", "/NeedAppearances")):
        score += 5
        reasons.append("minor_active_form_or_uri_signal")
    return ScoreResult(score=score, verdict=verdict_for_score(score, reasons), reasons=reasons)


def verdict_for_score(score: int, reasons: list[str]) -> str:
    if not reasons:
        return "no_findings"
    if score >= 100:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "suspicious"
    return "low"
