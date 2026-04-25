from __future__ import annotations

import re
import socket
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class ClamAVStatus:
    status: str
    version: str | None = None
    socket_path: str | None = None
    tcp: tuple[str, int] | None = None
    error: str | None = None
    stream_max_length: int | None = None


class ClamAVClient:
    def __init__(self, status: ClamAVStatus, *, enabled: bool) -> None:
        self.status = status
        self.enabled = enabled and status.status == "ok"

    @classmethod
    def discover(cls, socket_spec: str = "auto", *, enabled: bool = True) -> "ClamAVClient":
        if not enabled:
            return cls(ClamAVStatus("disabled"), enabled=False)
        candidates = _socket_candidates(socket_spec)
        for candidate in candidates:
            if candidate.startswith("tcp://"):
                host, port_text = candidate.removeprefix("tcp://").rsplit(":", 1)
                status = _check_tcp(host, int(port_text))
                if status.status == "ok":
                    return cls(status, enabled=True)
                continue
            path = Path(candidate)
            if path.exists():
                status = _check_unix(path)
                if status.status == "ok":
                    return cls(status, enabled=True)
        fallback = _clamscan_version()
        if fallback:
            return cls(ClamAVStatus("clamscan", version=fallback), enabled=True)
        return cls(ClamAVStatus("unavailable", error="clamd socket and clamscan not found"), enabled=False)

    def scan_file(self, path: Path) -> dict:
        if self.status.status == "disabled":
            return {"status": "disabled", "signature": None}
        if self.status.status == "unavailable":
            return {"status": "unavailable", "signature": None, "error": self.status.error}
        try:
            if self.status.status == "ok" and self.status.socket_path:
                return _instream_unix(Path(self.status.socket_path), path.read_bytes())
            if self.status.status == "ok" and self.status.tcp:
                host, port = self.status.tcp
                return _instream_tcp(host, port, path.read_bytes())
            return _clamscan(path)
        except OSError as exc:
            return {"status": "error", "signature": None, "error": str(exc)}

    def scan_bytes(self, data: bytes) -> dict:
        if self.status.status == "disabled":
            return {"status": "disabled", "signature": None}
        if self.status.status == "unavailable":
            return {"status": "unavailable", "signature": None, "error": self.status.error}
        try:
            if self.status.status == "ok" and self.status.socket_path:
                return _instream_unix(Path(self.status.socket_path), data)
            if self.status.status == "ok" and self.status.tcp:
                host, port = self.status.tcp
                return _instream_tcp(host, port, data)
        except OSError as exc:
            return {"status": "error", "signature": None, "error": str(exc)}
        return {"status": "unavailable", "signature": None, "error": "byte scan requires clamd"}


def _socket_candidates(socket_spec: str) -> list[str]:
    if socket_spec != "auto":
        return [socket_spec]
    candidates: list[str] = []
    for path in (Path("/etc/clamav/clamd.conf"), Path("/etc/clamd.conf")):
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in re.finditer(r"^\s*LocalSocket\s+(.+)$", text, re.M):
            candidates.append(match.group(1).strip())
        tcp_socket = re.search(r"^\s*TCPSocket\s+(\d+)$", text, re.M)
        tcp_addr = re.search(r"^\s*TCPAddr\s+(\S+)$", text, re.M)
        if tcp_socket:
            candidates.append(f"tcp://{tcp_addr.group(1) if tcp_addr else '127.0.0.1'}:{tcp_socket.group(1)}")
    candidates.extend(["/var/run/clamav/clamd.ctl", "/run/clamav/clamd.ctl"])
    return candidates


def _check_unix(path: Path) -> ClamAVStatus:
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            sock.connect(path.as_posix())
            version = _clamd_command(sock, b"zVERSION\0")
        return ClamAVStatus("ok", version=version, socket_path=path.as_posix())
    except OSError as exc:
        return ClamAVStatus("unavailable", error=str(exc))


def _check_tcp(host: str, port: int) -> ClamAVStatus:
    try:
        with socket.create_connection((host, port), timeout=2) as sock:
            version = _clamd_command(sock, b"zVERSION\0")
        return ClamAVStatus("ok", version=version, tcp=(host, port))
    except OSError as exc:
        return ClamAVStatus("unavailable", error=str(exc))


def _clamd_command(sock: socket.socket, command: bytes) -> str:
    sock.sendall(command)
    return sock.recv(4096).decode("utf-8", errors="replace").strip("\0\r\n")


def _instream_unix(path: Path, data: bytes) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(15)
        sock.connect(path.as_posix())
        return _instream(sock, data)


def _instream_tcp(host: str, port: int, data: bytes) -> dict:
    with socket.create_connection((host, port), timeout=15) as sock:
        return _instream(sock, data)


def _instream(sock: socket.socket, data: bytes) -> dict:
    sock.sendall(b"zINSTREAM\0")
    for offset in range(0, len(data), 1024 * 1024):
        chunk = data[offset : offset + 1024 * 1024]
        sock.sendall(struct.pack("!I", len(chunk)) + chunk)
    sock.sendall(struct.pack("!I", 0))
    response = sock.recv(4096).decode("utf-8", errors="replace").strip("\0\r\n")
    return _parse_clam_response(response)


def _clamscan_version() -> str | None:
    try:
        result = subprocess.run(["clamscan", "--version"], check=False, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() or None


def _clamscan(path: Path) -> dict:
    try:
        result = subprocess.run(
            ["clamscan", "--no-summary", path.as_posix()],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"status": "error", "signature": None, "error": str(exc)}
    return _parse_clam_response(result.stdout.strip() or result.stderr.strip())


def _parse_clam_response(response: str) -> dict:
    if " FOUND" in response:
        signature = response.rsplit(":", 1)[-1].replace("FOUND", "").strip()
        return {"status": "infected", "signature": signature}
    if response.endswith("OK") or " OK" in response:
        return {"status": "ok", "signature": None}
    return {"status": "error", "signature": None, "response": response}
