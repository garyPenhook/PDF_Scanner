from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Iterator

from .config import AppConfig
from .models import FileRecord


def _is_excluded(path: Path, config: AppConfig, regexes: list[re.Pattern[str]]) -> bool:
    try:
        resolved = path.resolve(strict=False)
    except OSError:
        resolved = path.absolute()
    for excluded in config.exclude:
        try:
            if resolved == excluded or resolved.is_relative_to(excluded):
                return True
        except OSError:
            continue
    text = resolved.as_posix()
    return any(regex.search(text) for regex in regexes)


def _is_pdf_candidate(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            header = fh.read(1024)
    except OSError:
        return False
    offset = header.find(b"%PDF-")
    if offset == 0:
        return True
    return offset > 0 and path.suffix.lower() == ".pdf"


def discover(config: AppConfig) -> Iterator[FileRecord]:
    regexes = [re.compile(pattern) for pattern in config.exclude_regex]
    seen_inodes: set[tuple[int, int]] = set()
    for root in config.roots:
        root = root.expanduser()
        try:
            root_stat = root.stat()
        except OSError:
            continue
        if stat.S_ISREG(root_stat.st_mode):
            if _is_pdf_candidate(root):
                yield FileRecord(root, root.resolve(strict=False), root_stat)
            continue
        if not stat.S_ISDIR(root_stat.st_mode):
            continue
        root_dev = root_stat.st_dev
        for dirpath, dirnames, filenames in os.walk(root, followlinks=config.follow_symlinks):
            current = Path(dirpath)
            depth = len(current.relative_to(root).parts) if current != root else 0
            if depth >= config.max_depth:
                dirnames[:] = []
            dirnames[:] = [
                d
                for d in dirnames
                if not _is_excluded(current / d, config, regexes)
                and (
                    not config.one_file_system
                    or _safe_stat(current / d, follow=config.follow_symlinks).st_dev == root_dev
                )
            ]
            for name in filenames:
                path = current / name
                if _is_excluded(path, config, regexes):
                    continue
                try:
                    st = path.stat() if config.follow_symlinks else path.lstat()
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                key = (st.st_dev, st.st_ino)
                if key in seen_inodes:
                    continue
                seen_inodes.add(key)
                if config.one_file_system and st.st_dev != root_dev:
                    continue
                if _is_pdf_candidate(path):
                    yield FileRecord(path, path.resolve(strict=False), st)


def _safe_stat(path: Path, *, follow: bool) -> os.stat_result:
    try:
        return path.stat() if follow else path.lstat()
    except OSError:
        return os.stat_result((0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
