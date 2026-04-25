from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class YaraEngine:
    enabled: bool
    status: str = "disabled"
    error: str | None = None
    matches_compile_errors: list[str] = field(default_factory=list)
    _rules: object | None = None

    @classmethod
    def build(cls, rule_dirs: list[Path], compiled_path: Path, *, enabled: bool, required: bool) -> "YaraEngine":
        if not enabled:
            return cls(enabled=False, status="disabled")
        try:
            import yara  # type: ignore
        except ImportError as exc:
            status = "required_unavailable" if required else "unavailable"
            return cls(enabled=False, status=status, error=str(exc))

        files: dict[str, str] = {}
        errors: list[str] = []
        for directory in rule_dirs:
            if not directory.exists():
                continue
            for path in sorted(directory.rglob("*.yar")) + sorted(directory.rglob("*.yara")):
                namespace = _namespace(path)
                files[namespace] = path.as_posix()
        if not files:
            return cls(enabled=False, status="no_rules")
        try:
            rules = yara.compile(filepaths=files)
            compiled_path.parent.mkdir(parents=True, exist_ok=True)
            rules.save(compiled_path.as_posix())
        except Exception as exc:  # yara raises its own extension exceptions
            if required:
                return cls(enabled=False, status="required_compile_failed", error=str(exc))
            errors.append(str(exc))
            return cls(enabled=False, status="compile_failed", error=str(exc), matches_compile_errors=errors)
        return cls(enabled=True, status="ok", _rules=rules, matches_compile_errors=errors)

    def match_file(self, path: Path) -> list[str]:
        if self._rules is None:
            return []
        try:
            return [match.rule for match in self._rules.match(path.as_posix())]  # type: ignore[attr-defined]
        except Exception:
            return []

    def match_data(self, data: bytes) -> list[str]:
        if self._rules is None or not data:
            return []
        try:
            return [match.rule for match in self._rules.match(data=data)]  # type: ignore[attr-defined]
        except Exception:
            return []


def _namespace(path: Path) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in path.with_suffix("").as_posix())[-120:]
