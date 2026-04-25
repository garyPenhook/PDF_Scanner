from pdfscan.scoring import score_indicators


def test_openaction_javascript_is_suspicious() -> None:
    result = score_indicators(
        tag_counts={"/OpenAction": 1, "/JavaScript": 1},
        structure_reasons=[],
        structure_hints={},
        yara_matches=[],
        clamav_signature=None,
        ioc_hit=False,
        js_suspicious=True,
        uri_blocklist_hits=0,
        parser_status="ok",
        encrypted=False,
    )

    assert result.verdict == "suspicious"
    assert "openaction+js" in result.reasons


def test_encrypted_is_unknown_not_clean() -> None:
    result = score_indicators(
        tag_counts={},
        structure_reasons=[],
        structure_hints={},
        yara_matches=[],
        clamav_signature=None,
        ioc_hit=False,
        js_suspicious=False,
        uri_blocklist_hits=0,
        parser_status="unknown_encrypted",
        encrypted=True,
    )

    assert result.verdict == "unknown"
    assert result.reasons == ["unknown_encrypted"]
