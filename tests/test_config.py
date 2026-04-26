from pathlib import Path

from pdfscan.config import default_scan_roots


def test_default_scan_roots_include_entire_home_tree() -> None:
    roots = default_scan_roots()

    assert roots[0] == Path("/home")
    assert Path.home() not in roots
