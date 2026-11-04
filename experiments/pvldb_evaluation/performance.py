"""Reproducible scale, recipient and dependent-tool measurements."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import math
import os
import re
import subprocess
import urllib.request
from contextlib import redirect_stdout
from pathlib import Path

from tn_governed.native_run import ALL_GPU_LAYERS

from .performance_manifest import environment_manifest
from .performance_scale import accounting, run_scale
from .performance_stats import elapsed_processing, save_json, statistics_summary, summarize_scale

TOOL_CONTRACT = (
    "Each trial executes fresh SQL/Polars/scalar processing, one native model "
    "workflow when enabled, and the configured chain of dependent receipt tools. "
    "Depth counts the native compliance tool plus subsequent dependent receipt calls; "
    "section-selection and report-emission model "
    "turns are not application tool calls. "
    "End-to-end time sums active stages, excluding setup, model endpoint configuration, "
    "startup, "
    "offline verification and artifact export. Tool choices follow a fixed schedule."
)


def validate_profile(profile):
    for name in ("rows", "recipients", "tool_depths"):
        values = profile.get(name)
        if (
            not isinstance(values, list)
            or not values
            or any(type(v) is not int or v < 1 for v in values)
            or len(set(values)) != len(values)
        ):
            raise ValueError(f"{name} must contain distinct positive integers")
    for name in ("recipient_rows", "tool_rows", "repetitions", "recipient_repetitions"):
        if type(profile.get(name)) is not int or profile[name] < 1:
            raise ValueError(f"{name} must be a positive integer")
    if type(profile.get("warmups")) is not int or profile["warmups"] < 0:
        raise ValueError("warmups must be a nonnegative integer")
    if type(profile.get("model")) is not bool:
        raise ValueError("model must be an explicit boolean")
    if type(profile.get("retain_cases", True)) is not bool:
        raise ValueError("retain_cases must be a boolean")
    if type(profile.get("gpu_layers", ALL_GPU_LAYERS)) is not int or profile.get("gpu_layers", ALL_GPU_LAYERS) < 1:
        raise ValueError("gpu_layers must be a positive integer; the model runs on the GPU")
    _validate_batches(profile)
    if "runtime_limits" in profile:
        from tn_governed.values.model import resolve_runtime_limits

        resolve_runtime_limits(profile["runtime_limits"])


def _validate_batches(profile):
    from tn_governed.values.primitives import MAX_SOURCE_PUBLICATION_CELLS

    batch_size = profile.get("sql_batch_size", 64)
    if type(batch_size) is not int or not 1 <= batch_size <= MAX_SOURCE_PUBLICATION_CELLS:
        raise ValueError("sql_batch_size exceeds the supported publication size")
    largest = max(*profile["rows"], profile["recipient_rows"], profile["tool_rows"])
    editions = 2 * math.ceil(largest / batch_size)
    if editions > 1024:
        raise ValueError(
            f"workload requires {editions} dataset bindings; "
            "increase sql_batch_size to stay within the native 1024-binding limit"
        )


def validate_model_revision(version):
    match = re.search(r"\bcommit ([0-9a-f]{7,40})\b", version)
    if match is None or not "3f545beccee69d9975f466ec7e45fd9aacd8ba90".startswith(match[1]):
        raise ValueError("model server does not report the pinned llama.cpp revision")
    return match[1]


def preflight(args, profile):
    from tn_governed.values.model import digest

    from .performance_env import native_module_path

    repository = Path(__file__).resolve().parents[2]
    build_record = Path(
        getattr(args, "sdk_build_record", None) or repository / "config/sdk-build.json"
    )
    build = json.loads(build_record.read_text(encoding="utf-8"))
    native = native_module_path()
    if (
        importlib.metadata.version("tn-proto") != build["version"]
        or digest(native) != build["install"]["native_module_sha256"]
    ):
        raise ValueError("installed native SDK does not match the selected build record")
    opa = args.opa or os.environ.get("TN_POLARS_OPA")
    if not opa or not Path(opa).is_file():
        raise ValueError("configure --opa or TN_POLARS_OPA with an installed OPA executable")
    opa_version = subprocess.run(
        [str(opa), "version"], check=True, capture_output=True, text=True, timeout=20
    ).stdout
    with urllib.request.urlopen(
        args.unity_url.rstrip("/") + "/api/2.1/unity-catalog/catalogs?max_results=1", timeout=5
    ) as reply:
        json.load(reply)
    result = {
        "native_sdk": "matched",
        "unity": "ready",
        "opa_version": opa_version,
        "model_versions": {},
    }
    if profile["model"]:
        result["model_versions"] = {name: _model_version(getattr(args, name).resolve())
                                    for name in ("binary", "plain_binary")}
    return result


def _model_version(binary):
    """The server's reported version, which must name the pinned llama.cpp revision."""
    from tn_governed.native_run import wsl_command, wsl_path

    from .performance_env import implementation_library, model_uses_wsl

    command = (
        [*wsl_command(), wsl_path(binary), "--version"]
        if model_uses_wsl(binary)
        else [str(binary), "--version"]
    )
    completed = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
    version = completed.stdout + completed.stderr
    validate_model_revision(version)
    implementation_library(binary)
    return version


def run_tool_workloads(root, args, profile):
    root.mkdir(parents=True, exist_ok=False)
    cases = []
    for repetition in range(-profile["warmups"], profile["repetitions"]):
        for depth in profile["tool_depths"]:
            case = _tool_case(root, args, profile, depth, repetition)
            cases.append(case)
            with (root / "samples.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(case, allow_nan=False) + "\n")
            if not case["ok"]:
                save_json(root / "results.json", {"completed": False, "cases": cases})
                raise RuntimeError(f"tool workload failed; inspect {case['directory']}")
    result = {
        "completed": True,
        "cases": cases,
        "aggregates": _tool_aggregates(profile, cases),
        "contract": TOOL_CONTRACT,
    }
    save_json(root / "results.json", result)
    return result


def _tool_case(root, args, profile, depth, repetition):
    from .run import run_case

    name = f"depth-{depth}-{'warmup' if repetition < 0 else 'sample'}-{abs(repetition)}"
    directory = root / name
    print(name, flush=True)
    with (root / f"{name}.log").open("w", encoding="utf-8") as log, redirect_stdout(log):
        summary = run_case(
            directory, "primitive", rows=profile["tool_rows"], depth=1, model=profile["model"],
            unity_url=args.unity_url, binary=args.binary, model_path=args.model_path,
            port=args.port, storage="files", gpu_layers=profile.get("gpu_layers", ALL_GPU_LAYERS),
            runtime_limits=profile.get("runtime_limits"),
            sdk_build_record=getattr(args, "sdk_build_record", None),
            sql_batch_size=profile.get("sql_batch_size", 64),
            completion_handler=_tool_completion(profile, depth),
        )
    case = {"depth": depth, "warmup": repetition < 0, "repetition": repetition,
            "directory": str(directory), "summary": summary,
            "ok": bool(summary["completed"] and summary["verified"])}
    if case["ok"]:
        case["end_to_end_seconds"] = elapsed_processing(summary["timings_seconds"], model=profile["model"])
        case["accounting"] = accounting(directory)
        case["signed_records"] = (case["accounting"]["signed_context_records"]
                                  + summary["completion"]["integrated_signed_records"])
    return case


def _tool_completion(profile, depth):
    """The completion handler: the native tool, then dependent receipts up to `depth`."""
    from .performance_tools import integrate_chain

    def complete(context, report, brief, case_root):
        native_count = len(report.release.tool_objects) if report is not None else 0
        if native_count != int(profile["model"]):
            raise AssertionError("native prerequisite count differs from the workload")
        additional = depth - native_count
        if additional:
            completion = integrate_chain(context, report, brief, additional, case_root / "tool-chain")
        else:
            completion = {"completed": True, "verified": True, "processing_seconds": 0,
                          "integrated_signed_records": 0, "observed_depth": 0}
        if not completion.get("completed") or not completion.get("verified"):
            completion["native_tool_count"] = native_count
            return completion
        observed = completion["observed_depth"] + native_count
        if observed != depth:
            raise AssertionError("observed application tool depth differs from requested depth")
        completion.update(native_tool_count=native_count, total_tool_depth=observed)
        return completion

    return complete


def _tool_aggregates(profile, cases):
    aggregates = []
    for depth in profile["tool_depths"]:
        measured = [c for c in cases if c["depth"] == depth and not c["warmup"]]
        aggregates.append({
            "depth": depth,
            "end_to_end_seconds": statistics_summary([c["end_to_end_seconds"] for c in measured]),
            "signed_records": statistics_summary([c["signed_records"] for c in measured]),
            "tool_seconds": statistics_summary([c["summary"]["timings_seconds"]["tools"] for c in measured]),
        })
    baseline = next(
        (a["end_to_end_seconds"]["median"] for a in aggregates if a["depth"] == 1), None
    )
    for item in aggregates:
        item["overhead_vs_depth_1"] = (
            item["end_to_end_seconds"]["median"] / baseline if baseline else None
        )
    return aggregates


def _arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, default=Path("config/performance.json"))
    parser.add_argument("--run-directory", type=Path, required=True)
    parser.add_argument("--unity-url", default="http://127.0.0.1:18080")
    parser.add_argument("--opa", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--plain-binary", type=Path)
    parser.add_argument("--model-path", type=Path)
    parser.add_argument(
        "--sdk-build-record", type=Path, help="Expected installed native SDK build record"
    )
    parser.add_argument("--port", type=int, default=18325)
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args(argv)
    profile = json.loads(args.profile.read_text(encoding="utf-8"))
    validate_profile(profile)
    if not 1 <= args.port <= 65535:
        parser.error("port must be in 1..65535")
    if args.opa:
        os.environ["TN_POLARS_OPA"] = str(args.opa.resolve())
    if profile["model"]:
        for name in ("binary", "plain_binary", "model_path"):
            path = getattr(args, name)
            if path is None or not path.is_file():
                parser.error(f"--{name.replace('_', '-')} must name a file for model measurements")
    return args, profile


def _measure(root, args, profile):
    """Run the scale, recipient, and tool studies; the outcome is saved even after a failure."""
    outcome = {"completed": False}
    try:
        cases, sources = run_scale(root, args, profile)
        from .performance_recipients import run_recipients

        outcome["scale"] = summarize_scale(cases)
        outcome["recipients"] = []
        for concurrency in profile["recipients"]:
            outcome["recipients"].append(run_recipients(
                sources[profile["recipient_rows"]], root / f"recipients-{concurrency}",
                concurrency, profile["recipient_repetitions"], profile["warmups"],
            ))
        outcome["tools"] = run_tool_workloads(root / "tools", args, profile)
        outcome["completed"] = (
            all(r["status"] == "completed" for r in outcome["recipients"])
            and outcome["tools"]["completed"]
        )
    finally:
        save_json(root / "results.json", outcome)
    return outcome


def main(argv=None):
    args, profile = _arguments(argv)
    root = args.run_directory.resolve()
    root.mkdir(parents=True, exist_ok=False)
    save_json(root / "experiment.json", environment_manifest(args, profile))
    try:
        save_json(root / "preflight.json", {"completed": True, **preflight(args, profile)})
    except Exception as exc:
        save_json(root / "preflight.json", {"completed": False, "error_type": type(exc).__name__})
        raise
    if args.preflight_only:
        print(root / "experiment.json")
        return 0
    outcome = _measure(root, args, profile)
    print(root / "results.json")
    return 0 if outcome["completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
