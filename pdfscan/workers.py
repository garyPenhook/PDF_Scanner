from __future__ import annotations

import multiprocessing as mp
import queue
import traceback
from pathlib import Path
from typing import Any, Callable


def run_with_timeout(func: Callable[..., Any], args: tuple, timeout: int) -> tuple[str, Any]:
    context = mp.get_context("spawn")
    result_queue: mp.Queue = context.Queue(maxsize=1)
    process = context.Process(target=_child_main, args=(result_queue, func, args))
    process.start()
    process.join(timeout)
    if process.is_alive():
        process.terminate()
        process.join(2)
        if process.is_alive():
            process.kill()
            process.join(2)
        return ("timeout", None)
    try:
        return result_queue.get_nowait()
    except queue.Empty:
        return ("crash", f"worker exited with code {process.exitcode}")


def _child_main(result_queue: mp.Queue, func: Callable[..., Any], args: tuple) -> None:
    try:
        result_queue.put(("ok", func(*args)))
    except BaseException as exc:
        result_queue.put(("error", {"error": str(exc), "traceback": traceback.format_exc()}))


def path_arg(path: str | Path) -> Path:
    return Path(path)
