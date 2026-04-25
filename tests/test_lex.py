from pdfscan.lex import scan_bytes


def test_normalizes_hex_escaped_pdf_names() -> None:
    data = b"%PDF-1.7\n1 0 obj << /J#53 (x) /Java#53cript (y) /Open#41ction 2 0 R >> endobj\n%%EOF"

    result = scan_bytes(data)

    assert result.tag_counts["/JS"] == 1
    assert result.tag_counts["/JavaScript"] == 1
    assert result.tag_counts["/OpenAction"] == 1


def test_detects_polyglot_and_multiple_eof() -> None:
    data = b"junk\x00%PDF-1.4\n%%EOF\n%%EOF\n"

    result = scan_bytes(data)

    assert result.header_offset == 5
    assert result.raw_counts["eof"] == 2
