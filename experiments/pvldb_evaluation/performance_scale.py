"""The scale study: TN and plain cases alternate in each repetition at every row count."""

from __future__ import annotations

import json
import shutil
import time
import traceback
from contextlib import redirect_stdout
from pathlib import Path

from tn_governed.native_run import ALL_GPU_LAYERS

from .performance_stats import (
    elapsed_processing,
    peak_memory_bytes,
    reset_peak_memory,
    save_json,
    summarize_scale,
)
from .study_summary import model_turns, native_timeline


def accounting(directory):
    from tn_governed.publications import open_publication_store
    from tn_governed.values.references import unpack_references

    manifest = json.loads((directory / "run.json").read_text(encoding="utf-8"))
    with open_publication_store(directory / "publications", read_only=True) as store:
        sizes = store.publication_sizes()
        if "sources" in manifest:
            refs = {json.dumps(item, sort_keys=True)
                    for item in unpack_references(manifest["sources"])}
        else:
            source_ids = {item["source_object_id"] for item in manifest["source_editions"]}
            refs = {(identity, field) for identity in source_ids
                    for field in store.read(identity).envelope["values"]["field_hashes"]}
    records = sum(tape["count"] for tape in manifest["tapes"].values())
    target = manifest["outputs"]["model_input"]["reference"]["object_id"]
    policy_refs = {
        policy if isinstance(policy, str) else policy["policy_revision"]
        for frame in manifest["evaluation"]["dataframe"]
        for policy in frame.get("policy_artifacts", frame.get("policies", []))
    }
    return {
        "direct_cell_refs": len(refs),
        "source_policy_refs": sorted(policy_refs),
        "source_policies": len(policy_refs),
        "signed_context_records": records,
        "retained_native_objects": len(sizes),
        "retained_native_bytes": sum(sizes.values()),
        "retained_native_kb": sum(sizes.values()) / 1000,
        "scalar_publication_bytes": sizes[target],
    }


def run_scale(root, args, profile):
    """Run every scale case once; the first failed case stops the study after it is recorded."""
    cases, source_runs = [], {}
    requested_rows = list(
        dict.fromkeys(profile["rows"] + [profile["recipient_rows"], profile["tool_rows"]])
    )
    for repetition in range(-profile["warmups"], profile["repetitions"]):
        for rows in requested_rows:
            for mode in ("tn", "plain") if repetition % 2 == 0 else ("plain", "tn"):
                case = _measure_case(
                    root, args, profile, (rows, mode, repetition), cases, source_runs)
                cases.append(case)
                _record_case(root, profile, case, cases)
                if not case["ok"]:
                    raise RuntimeError(f"measurement failed; inspect {case['directory']}")
    return cases, source_runs


def _measure_case(root, args, profile, workload, cases, source_runs):
    """Run one case and return its observation; a failure is recorded, not raised."""
    rows, mode, repetition = workload
    name = f"rows-{rows}-{mode}-{'warmup' if repetition < 0 else 'sample'}-{abs(repetition)}"
    directory = root / name
    print(name, flush=True)
    case = {"rows": rows, "mode": mode, "repetition": repetition, "warmup": repetition < 0,
            "directory": str(directory), "ok": False, "seconds": None}
    attempt_start = time.perf_counter()
    reset_peak_memory()
    try:
        with (root / f"{name}.log").open("w", encoding="utf-8") as log, redirect_stdout(log):
            summary = _run_mode(directory, args, profile, rows, mode)
        _accept_summary(case, summary, directory, profile, cases, source_runs)
    except Exception as exc:
        case["ok"] = False
        case["error_type"] = type(exc).__name__
        (root / f"{name}.error.log").write_text(traceback.format_exc(), encoding="utf-8")
    case["attempt_wall_seconds"] = time.perf_counter() - attempt_start
    case["peak_rss_bytes"] = peak_memory_bytes()
    if mode == "tn" and directory.exists():
        # The summary reads these after the case directory may be removed.
        case["model_turns"] = model_turns(directory)
        case["native_timeline"] = native_timeline(directory)
    return case


def _run_mode(directory, args, profile, rows, mode):
    from .performance_model import ordinary_model_case
    from .processing_comparison import ordinary_case
    from .run import run_case

    gpu_layers = profile.get("gpu_layers", ALL_GPU_LAYERS)
    if mode == "tn":
        return run_case(
            directory, "primitive", rows=rows, depth=1, model=profile["model"],
            unity_url=args.unity_url, binary=args.binary, model_path=args.model_path,
            port=args.port, storage="files", gpu_layers=gpu_layers,
            runtime_limits=profile.get("runtime_limits"),
            sdk_build_record=getattr(args, "sdk_build_record", None),
            sql_batch_size=profile.get("sql_batch_size", 64),
        )
    if profile["model"]:
        return ordinary_model_case(directory, rows, binary=args.plain_binary, model=args.model_path,
                                   port=args.port, gpu_layers=gpu_layers)
    return ordinary_case(directory, rows)


def _accept_summary(case, summary, directory, profile, cases, source_runs):
    """A verified case keeps its latency, accounting, and content, which must match its peers."""
    case["summary"] = summary
    case["ok"] = bool(summary["completed"] and summary["verified"])
    if not case["ok"]:
        return
    case["seconds"] = elapsed_processing(summary["timings_seconds"], model=profile["model"])
    case["content"] = summary["expected_content"]
    if case["mode"] == "tn":
        case["accounting"] = accounting(directory)
        if case["accounting"]["direct_cell_refs"] != 2 * case["rows"]:
            raise AssertionError("source reference count differs from workload")
        if case["accounting"]["source_policies"] != 2:
            raise AssertionError("source policy count differs from workload")
        if case["repetition"] >= 0:
            source_runs.setdefault(case["rows"], directory)
    peers = [c for c in cases if c["rows"] == case["rows"] and c["ok"]]
    if any(c["content"] != case["content"] for c in peers):
        raise AssertionError("plain and TN calculations differ")


def _record_case(root, profile, case, cases):
    directory = Path(case["directory"])
    if (not profile.get("retain_cases", True) and directory.exists()
            and case["rows"] not in (profile["recipient_rows"], profile["tool_rows"])):
        # Its measurements are recorded; no later study reads this run.
        shutil.rmtree(directory)
    with (root / "samples.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(case, allow_nan=False) + "\n")
    save_json(root / "scale.json", {"cases": cases, "aggregates": summarize_scale(cases)})
    print(json.dumps({k: case[k] for k in ("rows", "mode", "ok", "seconds")}), flush=True)
