"""Measurement summaries, processing latency, and per-case peak memory."""

from __future__ import annotations

import ctypes
import gc
import json
import math
import re
import statistics
from pathlib import Path

PROCESS_STAGES = ("query", "claim", "dataframe", "compute", "console_disclosure")


def statistics_summary(values):
    values = sorted(values)
    if not values:
        return None
    if any(not math.isfinite(v) or v < 0 for v in values):
        raise ValueError("measurements must be finite and nonnegative")
    return {
        "n": len(values),
        "median": statistics.median(values),
        "p95": values[math.ceil(0.95 * len(values)) - 1],
        "min": values[0],
        "max": values[-1],
    }


def reset_peak_memory():
    """Restart the kernel's peak-resident counter for this process on Linux.

    Memory freed by earlier cases is first returned to the system, so a case's peak
    starts from the live set rather than from pages the allocator kept.
    """
    gc.collect()
    try:
        ctypes.CDLL("libc.so.6").malloc_trim(0)
    except OSError:
        pass
    try:
        Path("/proc/self/clear_refs").write_text("5", encoding="ascii")
    except OSError:
        return


def peak_memory_bytes():
    """Return this process's peak resident set since the last reset, when reported."""
    try:
        status = Path("/proc/self/status").read_text(encoding="ascii")
    except OSError:
        return None
    match = re.search(r"^VmHWM:\s+(\d+) kB$", status, re.MULTILINE)
    return int(match[1]) * 1024 if match else None


def elapsed_processing(timings, *, model):
    """Processing latency: the pipeline stages and tools, never model generation.

    Generation holds model inference, which is reported beside processing and never
    inside it or inside the TN-to-plain ratio.
    """
    if model and "generation" not in timings:
        raise ValueError("missing generation timing")
    return sum(timings.get(name, 0) for name in PROCESS_STAGES + ("tools",))


def summarize_scale(cases):
    result = []
    for rows in sorted({case["rows"] for case in cases}):
        item = {"rows": rows}
        for mode in ("tn", "plain"):
            attempts = [
                c for c in cases if c["rows"] == rows and c["mode"] == mode and not c["warmup"]
            ]
            successful = [c["seconds"] for c in attempts if c["ok"]]
            item[mode] = {
                "attempts": len(attempts),
                "failures": sum(not c["ok"] for c in attempts),
                "seconds": statistics_summary(successful),
            }
        a, b = item["tn"]["seconds"], item["plain"]["seconds"]
        item["tn_plain_ratio"] = (
            a["median"] / b["median"]
            if a
            and b
            and b["median"] > 0
            and not item["tn"]["failures"]
            and not item["plain"]["failures"]
            else None
        )
        result.append(item)
    return result


def save_json(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False), encoding="utf-8")
    temporary.replace(path)
