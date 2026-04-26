from __future__ import annotations

import importlib.util
import math
import os
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AccelerationStatus:
    cpu_count: int
    jobs: int
    gpu_mode: str
    gpu_available: bool
    gpu_backend: str
    gpu_name: str | None = None
    gpu_reason: str | None = None
    entropy_backend: str = "cpu"

    def to_json(self) -> dict[str, object]:
        return {
            "cpu_count": self.cpu_count,
            "jobs": self.jobs,
            "gpu_mode": self.gpu_mode,
            "gpu_available": self.gpu_available,
            "gpu_backend": self.gpu_backend,
            "gpu_name": self.gpu_name,
            "gpu_reason": self.gpu_reason,
            "entropy_backend": self.entropy_backend,
        }


_CUDA_HISTOGRAM_KERNEL = None
_CUDA_FAILURE: str | None = None


def detect_acceleration(gpu_mode: str, jobs: int) -> AccelerationStatus:
    cpu_count = os.cpu_count() or 1
    if gpu_mode == "off":
        return AccelerationStatus(
            cpu_count=cpu_count,
            jobs=jobs,
            gpu_mode=gpu_mode,
            gpu_available=False,
            gpu_backend="none",
            gpu_reason="disabled",
        )

    if importlib.util.find_spec("numba") is None:
        gpu_name = _nvidia_smi_name()
        return AccelerationStatus(
            cpu_count=cpu_count,
            jobs=jobs,
            gpu_mode=gpu_mode,
            gpu_available=False,
            gpu_backend="cuda",
            gpu_name=gpu_name,
            gpu_reason="numba.cuda is not installed",
        )

    try:
        from numba import cuda  # type: ignore

        if not cuda.is_available():
            gpu_name = _nvidia_smi_name()
            return AccelerationStatus(
                cpu_count=cpu_count,
                jobs=jobs,
                gpu_mode=gpu_mode,
                gpu_available=False,
                gpu_backend="cuda",
                gpu_name=gpu_name,
                gpu_reason="CUDA device is not available to numba",
            )
        device = cuda.get_current_device()
        raw_name = getattr(device, "name", None)
        name = (
            raw_name.decode("utf-8", errors="replace")
            if isinstance(raw_name, bytes)
            else raw_name
        )
        return AccelerationStatus(
            cpu_count=cpu_count,
            jobs=jobs,
            gpu_mode=gpu_mode,
            gpu_available=True,
            gpu_backend="cuda",
            gpu_name=str(name) if name else None,
            entropy_backend="cuda",
        )
    except Exception as exc:
        return AccelerationStatus(
            cpu_count=cpu_count,
            jobs=jobs,
            gpu_mode=gpu_mode,
            gpu_available=False,
            gpu_backend="cuda",
            gpu_name=_nvidia_smi_name(),
            gpu_reason=str(exc),
        )


def shannon_entropy_gpu(data: bytes) -> float | None:
    global _CUDA_FAILURE
    if not data or _CUDA_FAILURE is not None:
        return None
    try:
        import numpy as np  # type: ignore
        from numba import cuda  # type: ignore

        if not cuda.is_available():
            _CUDA_FAILURE = "CUDA unavailable"
            return None
        host_data = np.frombuffer(data, dtype=np.uint8)
        device_data = cuda.to_device(host_data)
        device_counts = cuda.to_device(np.zeros(256, dtype=np.uint32))
        threads_per_block = 256
        blocks = min(65535, max(1, math.ceil(host_data.size / threads_per_block)))
        _get_cuda_histogram_kernel(cuda)[blocks, threads_per_block](device_data, device_counts)
        cuda.synchronize()
        counts = device_counts.copy_to_host()
    except Exception as exc:
        _CUDA_FAILURE = str(exc)
        return None

    length = len(data)
    return -sum((int(count) / length) * math.log2(int(count) / length) for count in counts if count)


def _get_cuda_histogram_kernel(cuda):
    global _CUDA_HISTOGRAM_KERNEL
    if _CUDA_HISTOGRAM_KERNEL is None:

        @cuda.jit
        def histogram(data, counts):
            start = cuda.grid(1)
            stride = cuda.gridsize(1)
            for index in range(start, data.size, stride):
                cuda.atomic.add(counts, int(data[index]), 1)

        _CUDA_HISTOGRAM_KERNEL = histogram
    return _CUDA_HISTOGRAM_KERNEL


def _nvidia_smi_name() -> str | None:
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    names = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return ", ".join(names) if names else None
