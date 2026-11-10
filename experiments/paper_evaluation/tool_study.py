"""Tool-chain trials over a retained source, separating inherited model timings from tool cost."""

from __future__ import annotations

import hashlib
import json
import statistics
from datetime import UTC, datetime
from pathlib import Path

from .performance_tools import _admit_scalar, _save, measure_chain

MEASUREMENT_CONTRACT = {
    "workload": (
        "Dependent durable review-registration receipts "
        "over the retained model-input scalar"
    ),
    "depth": "Longest successful explicit tool-call dependency chain",
    "timed": (
        "ToolWorkflow construction, all tool checks and receipts, "
        "required ledger action, governed release"
    ),
    "untimed": (
        "Endpoint enrollment, retained-source import, final verification/disclosure, "
        "measurement export"
    ),
    "model": (
        "No model request in this interval; source model timing is retained separately"
    ),
    "bytes": (
        "Unique canonical native wire bytes; "
        "additions include snapshots and signed evidence"
    ),
    "records": (
        "Signed operation records added during the timed interval, "
        "excluding creation snapshots"
    ),
    "warmup": (
        "Fresh endpoint and store per trial; "
        "warmup trials are retained and excluded from summaries"
    ),
}


def _median(cases, key):
    return statistics.median(case[key] for case in cases) if cases else None


def summarize_tools(cases):
    summaries = []
    for depth in sorted({case["depth"] for case in cases}):
        measured = [case for case in cases if case["depth"] == depth and not case["warmup"]]
        successful = [case for case in measured if case["completed"] and case["verified"]]
        summaries.append({
            "depth": depth,
            "attempts": len(measured),
            "successful": len(successful),
            "failures": len(measured) - len(successful),
            "median_tool_seconds": _median(successful, "tool_seconds"),
            "median_signed_records": _median(successful, "signed_records"),
            "median_added_native_bytes": _median(successful, "added_native_bytes"),
        })
    baseline = next(
        (
            item["median_tool_seconds"]
            for item in summaries
            if item["depth"] == 1 and not item["failures"]
        ),
        None,
    )
    for item in summaries:
        item["tool_overhead_vs_depth_1"] = (
            item["median_tool_seconds"] / baseline
            if baseline and item["median_tool_seconds"] is not None and not item["failures"]
            else None
        )
    return summaries


def run_tools(source_directory, output_directory, depths=(1, 3, 5), repetitions=5, warmups=1):
    """Retain raw tool-chain trials and separate inherited model timings from tool cost."""
    depths = tuple(depths)
    if (
        not depths
        or any(type(depth) is not int or depth < 1 for depth in depths)
        or len(set(depths)) != len(depths)
        or type(repetitions) is not int
        or repetitions < 1
        or type(warmups) is not int
        or warmups < 0
    ):
        raise ValueError("depths must be unique positive integers with valid repetition counts")
    source_directory, root = Path(source_directory).resolve(), Path(output_directory).resolve()
    base = json.loads((source_directory / "case-summary.json").read_bytes())
    if not base.get("completed") or not base.get("verified"):
        raise ValueError("tool measurements require a completed verified source workload")
    root.mkdir(parents=True, exist_ok=False)
    result = {
        "schema": "tn.performance-tools.v1",
        "created_utc": datetime.now(UTC).isoformat(),
        "source_directory": str(source_directory),
        "source_rows": base["rows"],
        "source_with_model": base["with_model"],
        "source_timings_seconds": base["timings_seconds"],
        "source_summary_sha256": hashlib.sha256(
            (source_directory / "case-summary.json").read_bytes()
        ).hexdigest(),
        "measurement_contract": MEASUREMENT_CONTRACT,
        "depths": list(depths),
        "repetitions": repetitions,
        "warmups": warmups,
        "cases": [],
    }
    _save(root / "experiment.json", {key: value for key, value in result.items() if key != "cases"})
    for trial in range(warmups + repetitions):
        for depth in depths:
            case = _tool_trial(source_directory, root, depth, trial, warmups)
            result["cases"].append(case)
            with (root / "observations.jsonl").open("a", encoding="utf-8") as output:
                output.write(json.dumps(case, allow_nan=False) + "\n")
    result["aggregates"] = summarize_tools(result["cases"])
    result["completed"] = all(case["completed"] and case["verified"] for case in result["cases"])
    _save(root / "measurements.json", result)
    return result


def _tool_trial(source_directory, root, depth, trial, warmups):
    """One fresh recipient admits the retained source and runs the chain; failures are recorded."""
    from .performance_source import open_recipient, prepare_recipient

    warmup = trial < warmups
    name = f"{'warmup' if warmup else 'measured'}-{trial + 1}-depth-{depth}"
    directory = root / name
    stage = "enrollment"
    try:
        prepare_recipient(source_directory, directory)
        stage = "source_admission"
        with open_recipient(directory) as prepared:
            endpoint, admitted, _ = _admit_scalar(prepared["context"], prepared["value"])
            stage = "tool_chain"
            case = measure_chain(endpoint, admitted, depth, directory / "tool-chain")
    except Exception as exc:
        case = {
            "depth": depth,
            "completed": False,
            "verified": False,
            "error_type": type(exc).__name__,
            "error_stage": stage,
        }
        directory.mkdir(parents=True, exist_ok=True)
        _save(directory / "failure.json", case)
    return {**case, "warmup": warmup, "trial": trial + 1, "directory": name}
