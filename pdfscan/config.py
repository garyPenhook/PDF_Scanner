from __future__ import annotations

import argparse
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .util import parse_size


DEFAULT_EXCLUDES = [
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/tmp/.X11-unix",
    "/var/lib/docker",
    "/var/lib/containers",
    "/var/lib/lxc",
    "/var/lib/lxd",
    "/.snapshots",
    "/var/lib/clamav",
]


def default_scan_roots() -> list[Path]:
    roots = [
        Path("/home"),
        Path("/root"),
        Path("/tmp"),
        Path("/var/tmp"),
        Path("/opt"),
        Path("/srv"),
        Path("/media"),
        Path("/mnt"),
    ]
    return list(dict.fromkeys(roots))


@dataclass(slots=True)
class ClamAVConfig:
    enabled: bool = True
    required: bool = False
    socket: str = "auto"


@dataclass(slots=True)
class YaraConfig:
    enabled: bool = True
    required: bool = False
    extra_rule_dirs: list[Path] = field(default_factory=list)


@dataclass(slots=True)
class IOCConfig:
    hash_files: list[Path] = field(default_factory=lambda: [Path("pdfscan/rules/ioc_hashes.txt")])
    fuzzy: bool = False
    vt_hash_lookup: bool = False
    vt_submit_file: bool = False


@dataclass(slots=True)
class ReportConfig:
    formats: list[str] = field(default_factory=lambda: ["jsonl", "csv", "md"])
    min_score: int = 10


@dataclass(slots=True)
class AccelerationConfig:
    gpu: str = "auto"
    min_gpu_entropy_size: int = 4 * 1024 * 1024


@dataclass(slots=True)
class AppConfig:
    roots: list[Path] = field(default_factory=default_scan_roots)
    out_dir: Path | None = None
    include: list[Path] = field(default_factory=list)
    exclude: list[Path] = field(default_factory=lambda: [Path(p) for p in DEFAULT_EXCLUDES])
    exclude_regex: list[str] = field(default_factory=lambda: [r"/\.git/", r"/__pycache__/"])
    one_file_system: bool = True
    follow_symlinks: bool = False
    max_size: int = 256 * 1024 * 1024
    max_depth: int = 64
    jobs: int = max(1, min(8, os.cpu_count() or 1))
    timeout: int = 30
    worker_recycle: int = 200
    worker_memory_mb: int = 1024
    full: bool = False
    quiet: bool = False
    verbose: bool = False
    dry_run: bool = False
    as_root: bool = False
    worker_user: str | None = None
    quarantine_mode: str = "none"
    clamav: ClamAVConfig = field(default_factory=ClamAVConfig)
    yara: YaraConfig = field(default_factory=YaraConfig)
    ioc: IOCConfig = field(default_factory=IOCConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    acceleration: AccelerationConfig = field(default_factory=AccelerationConfig)


def default_config_paths() -> list[Path]:
    return [
        Path("pdfscan.toml"),
        Path.home() / ".config/pdfscan/config.toml",
        Path("/etc/pdfscan/config.toml"),
    ]


def _load_toml(path: Path) -> dict:
    with path.open("rb") as fh:
        return tomllib.load(fh)


def _as_paths(values: list[str] | tuple[str, ...] | None) -> list[Path]:
    return [Path(v).expanduser() for v in values or []]


def apply_mapping(config: AppConfig, data: dict) -> None:
    if "roots" in data:
        config.roots = _as_paths(data["roots"])
    if "out_dir" in data:
        config.out_dir = Path(data["out_dir"]).expanduser()
    if "exclude" in data:
        config.exclude = _as_paths(data["exclude"])
    if "include" in data:
        config.include = _as_paths(data["include"])
    if "exclude_regex" in data:
        config.exclude_regex = list(data["exclude_regex"])
    for key in ("one_file_system", "follow_symlinks", "max_depth", "jobs", "timeout"):
        if key in data:
            setattr(config, key, data[key])
    if "max_size" in data:
        config.max_size = parse_size(data["max_size"], config.max_size)
    if "worker_recycle" in data:
        config.worker_recycle = int(data["worker_recycle"])
    if "worker_memory_mb" in data:
        config.worker_memory_mb = int(data["worker_memory_mb"])
    if "quarantine" in data:
        qdata = data["quarantine"]
        if "mode" in qdata:
            config.quarantine_mode = qdata["mode"]
    if "clamav" in data:
        cdata = data["clamav"]
        config.clamav.enabled = bool(cdata.get("enabled", config.clamav.enabled))
        config.clamav.required = bool(cdata.get("required", config.clamav.required))
        config.clamav.socket = str(cdata.get("socket", config.clamav.socket))
    if "yara" in data:
        ydata = data["yara"]
        config.yara.enabled = bool(ydata.get("enabled", config.yara.enabled))
        config.yara.required = bool(ydata.get("required", config.yara.required))
        config.yara.extra_rule_dirs = _as_paths(ydata.get("extra_rule_dirs", []))
    if "ioc" in data:
        idata = data["ioc"]
        if "hash_file" in idata:
            config.ioc.hash_files = [Path(idata["hash_file"]).expanduser()]
        if "hash_files" in idata:
            config.ioc.hash_files = _as_paths(idata["hash_files"])
        config.ioc.fuzzy = bool(idata.get("fuzzy", config.ioc.fuzzy))
        config.ioc.vt_hash_lookup = bool(idata.get("vt_hash_lookup", config.ioc.vt_hash_lookup))
        config.ioc.vt_submit_file = bool(idata.get("vt_submit_file", config.ioc.vt_submit_file))
    if "report" in data:
        rdata = data["report"]
        if "formats" in rdata:
            config.report.formats = list(rdata["formats"])
        if "min_score" in rdata:
            config.report.min_score = int(rdata["min_score"])
    if "acceleration" in data:
        adata = data["acceleration"]
        if "gpu" in adata:
            config.acceleration.gpu = str(adata["gpu"])
        if "min_gpu_entropy_size" in adata:
            config.acceleration.min_gpu_entropy_size = parse_size(
                adata["min_gpu_entropy_size"],
                config.acceleration.min_gpu_entropy_size,
            )


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Defensive PDF malware scanner")
    ap.add_argument("paths", nargs="*", type=Path, help="Files or directories to scan")
    ap.add_argument("--config", type=Path)
    ap.add_argument("--out-dir", type=Path)
    ap.add_argument("--jobs", type=int)
    ap.add_argument("--max-size")
    ap.add_argument("--max-depth", type=int)
    ap.add_argument("--timeout", type=int)
    ap.add_argument("--worker-recycle", type=int)
    ap.add_argument("--worker-memory-mb", type=int)
    gpu = ap.add_mutually_exclusive_group()
    gpu.add_argument("--gpu", choices=["auto", "on", "off"])
    gpu.add_argument("--no-gpu", dest="gpu", action="store_const", const="off")
    fs = ap.add_mutually_exclusive_group()
    fs.add_argument("--one-file-system", dest="one_file_system", action="store_true")
    fs.add_argument("--no-one-file-system", dest="one_file_system", action="store_false")
    ap.set_defaults(one_file_system=None)
    ap.add_argument("--follow-symlinks", action="store_true")
    ap.add_argument("--include", action="append", type=Path, default=[])
    ap.add_argument("--exclude", action="append", type=Path, default=[])
    ap.add_argument("--exclude-regex", action="append", default=[])
    ap.add_argument("--as-root", "--full-system", dest="as_root", action="store_true")
    ap.add_argument("--worker-user")
    ap.add_argument("--no-clamav", action="store_true")
    ap.add_argument("--require-clamav", action="store_true")
    ap.add_argument("--no-yara", action="store_true")
    ap.add_argument("--require-yara", action="store_true")
    ap.add_argument("--rules", action="append", type=Path, default=[])
    ap.add_argument("--ioc-hashes", action="append", type=Path, default=[])
    ap.add_argument("--vt-hash-lookup", action="store_true")
    ap.add_argument("--vt-submit-file", action="store_true")
    ap.add_argument("--quarantine-mode", choices=["none", "copy", "hardlink"])
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--min-score", type=int)
    ap.add_argument("--format", dest="formats", help="Comma-separated: jsonl,csv,md")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    return ap


def load_config(argv: list[str] | None = None) -> AppConfig:
    ap = parser()
    args = ap.parse_args(argv)
    config = AppConfig()
    cfg_path = args.config
    if cfg_path is None:
        cfg_path = next((p for p in default_config_paths() if p.exists()), None)
    if cfg_path is not None and cfg_path.exists():
        apply_mapping(config, _load_toml(cfg_path))
    if args.paths:
        config.roots = args.paths
    if args.out_dir is not None:
        config.out_dir = args.out_dir
    for key in (
        "jobs",
        "max_depth",
        "timeout",
        "worker_recycle",
        "worker_memory_mb",
        "worker_user",
    ):
        value = getattr(args, key)
        if value is not None:
            setattr(config, key, value)
    if args.max_size is not None:
        config.max_size = parse_size(args.max_size, config.max_size)
    if args.gpu is not None:
        config.acceleration.gpu = args.gpu
    if args.one_file_system is not None:
        config.one_file_system = args.one_file_system
    if args.follow_symlinks:
        config.follow_symlinks = True
    if args.include:
        config.include.extend(args.include)
    if args.exclude:
        config.exclude.extend(args.exclude)
    if args.exclude_regex:
        config.exclude_regex.extend(args.exclude_regex)
    if args.as_root:
        config.as_root = True
        if not args.paths:
            config.roots = [Path("/")]
    if args.no_clamav:
        config.clamav.enabled = False
    if args.require_clamav:
        config.clamav.enabled = True
        config.clamav.required = True
    if args.no_yara:
        config.yara.enabled = False
    if args.require_yara:
        config.yara.enabled = True
        config.yara.required = True
    if args.rules:
        config.yara.extra_rule_dirs.extend(args.rules)
    if args.ioc_hashes:
        config.ioc.hash_files.extend(args.ioc_hashes)
    if args.vt_hash_lookup:
        config.ioc.vt_hash_lookup = True
    if args.vt_submit_file:
        config.ioc.vt_submit_file = True
    if args.quarantine_mode:
        config.quarantine_mode = args.quarantine_mode
    if args.full:
        config.full = True
    if args.min_score is not None:
        config.report.min_score = args.min_score
    if args.formats:
        config.report.formats = [part.strip() for part in args.formats.split(",") if part.strip()]
    config.quiet = args.quiet
    config.verbose = args.verbose
    config.dry_run = args.dry_run
    return config
