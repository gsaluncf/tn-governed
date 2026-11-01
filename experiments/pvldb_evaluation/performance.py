"""Reproducible scale, recipient and dependent-tool measurements."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import re
import statistics
import subprocess
import sys
import time
import traceback
import urllib.request
from contextlib import redirect_stdout
from datetime import UTC, datetime
from pathlib import Path

PROCESS_STAGES = ("query", "claim", "dataframe", "compute", "console_disclosure")


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
    if "runtime_limits" in profile:
        from tn_governed.values.model import resolve_runtime_limits

        resolve_runtime_limits(profile["runtime_limits"])


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


def elapsed_processing(timings, *, model):
    names = PROCESS_STAGES + (("generation",) if model else ()) + ("tools",)
    if model and "generation" not in timings:
        raise ValueError("missing generation timing")
    return sum(timings.get(name, 0) for name in names)


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


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def accounting(directory):
    from tn_governed.publications import open_publication_store

    manifest = json.loads((directory / "run.json").read_text(encoding="utf-8"))
    with open_publication_store(directory / "publications", read_only=True) as store:
        sizes = store.publication_sizes()
    sources = manifest["sources"]
    refs = {json.dumps(v["reference"], sort_keys=True) for v in sources}
    records = sum(tape["count"] for tape in manifest["tapes"].values())
    target = manifest["outputs"]["model_input"]["reference"]["object_id"]
    policy_refs = {
        policy["policy_revision"]
        for frame in manifest["evaluation"]["dataframe"]
        for policy in frame["policy_artifacts"]
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


def environment_manifest(args, profile):
    import re
    import sqlite3
    import ssl

    from .performance_env import native_module_path

    repository = Path(__file__).resolve().parents[2]

    def cmake_configuration(cache):
        options = {}
        for line in cache.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith(("#", "//")) or "=" not in line or ":" not in line:
                continue
            typed_name, value = line.split("=", 1)
            name = typed_name.split(":", 1)[0]
            if name.startswith(("CMAKE_", "GGML_", "LLAMA_")) or name == "BUILD_SHARED_LIBS":
                options[name] = value
        compilers = {}
        for path in sorted(cache.parent.glob("CMakeFiles/*/CMake*Compiler.cmake")):
            values = dict(
                re.findall(
                    r'set\((CMAKE_(?:C|CXX|CUDA)_COMPILER(?:_ID|_VERSION)?) "([^"]*)"\)',
                    path.read_text(encoding="utf-8", errors="replace"),
                )
            )
            compilers[str(path.relative_to(cache.parent))] = {
                "sha256": sha256(path),
                "identity": values,
            }
        return {
            "path": str(cache.resolve()),
            "sha256": sha256(cache),
            "options": options,
            "compiler_records": compilers,
        }

    manifest = {
        "schema": "tn.performance.v1",
        "created_utc": datetime.now(UTC).isoformat(),
        "profile": profile,
        "command": sys.argv,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "logical_cpus": os.cpu_count(),
        "python": sys.version,
        "packages": {
            p: importlib.metadata.version(p)
            for p in ("tn-proto", "polars", "tn-polars", "tn-llama-client", "wasmtime")
        },
        "git_head": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repository, text=True
        ).strip(),
        "git_status": subprocess.check_output(
            ["git", "status", "--short"], cwd=repository, text=True
        ),
        "source_sha256": {
            p.relative_to(repository).as_posix(): sha256(p)
            for folder in (
                repository / "experiments/pvldb_evaluation",
                repository / "src/tn_governed",
                repository / "dependencies/tn-polars/tn_polars",
            )
            for p in sorted(folder.rglob("*.py"))
        },
        "clock": "time.perf_counter_ns / time.perf_counter; elapsed wall time",
        "latency_summary": "median and nearest-rank p95 of raw successful samples",
        "scale_timing": {
            "included": list(PROCESS_STAGES)
            + (["generation"] if profile["model"] else []),
            "excluded": [
                "input database creation",
                "key provisioning",
                "catalog assignments",
                "model process startup",
                "native endpoint configuration and model artifact hashing",
                "offline verification",
                "artifact export",
            ],
            "native_prepare": "Separately timed endpoint configuration: ancestry serialization "
            "and model/binary hash reads; excluded from processing latency.",
            "generation": "Includes native protocol model turns, required tool, signed report, "
            "recipient acceptance and review queue registration.",
        },
        "cache": "Fresh sessions, stores and model process per scale case; OS file caches "
        "are not flushed. Warmup cases are retained and excluded from summaries. "
        "Prompt caching disabled on both model servers.",
        "baseline": "Ordinary SQLite/Polars/scalar calculation and one HTML generation. "
        "Same business input, GGUF, temperature=0 and final token ceiling; "
        "TN additionally executes its governance protocol turns and required actions.",
        "bytes": "Decimal KB=1000 bytes. Retained native bytes count each stored object once, "
        "including metadata, signed records and creation snapshots; tape copies excluded.",
        "records": "Signed context records counted from exported recorder checkpoints; "
        "native model tool publications reported separately.",
        "unity_url": args.unity_url,
        "services": {
            "wsl_distribution": os.environ.get("TN_WSL_DISTRO"),
            "polars_threads": os.environ.get("POLARS_MAX_THREADS"),
        },
    }
    if os.name == "nt":
        import ctypes
        import winreg

        class MemoryStatus(ctypes.Structure):
            _fields_ = [("length", ctypes.c_ulong), ("load", ctypes.c_ulong)] + [
                (name, ctypes.c_ulonglong)
                for name in (
                    "physical",
                    "available",
                    "page",
                    "available_page",
                    "virtual",
                    "available_virtual",
                    "extended",
                )
            ]

        memory = MemoryStatus()
        memory.length = ctypes.sizeof(memory)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)):
            manifest["physical_memory_bytes"] = memory.physical
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
        ) as key:
            manifest["cpu_model"] = winreg.QueryValueEx(key, "ProcessorNameString")[0].strip()
    for name in ("model_path", "binary", "plain_binary", "opa", "sdk_build_record"):
        path = getattr(args, name, None)
        if path:
            path = path.resolve()
            manifest[name] = {
                "path": str(path),
                "sha256": sha256(path),
                "bytes": path.stat().st_size,
            }
            if name in {"binary", "plain_binary"}:
                manifest[name]["adjacent_shared_libraries"] = {
                    library.name: {"sha256": sha256(library), "bytes": library.stat().st_size}
                    for library in sorted(path.parent.iterdir())
                    if library.is_file()
                    and (".so" in library.name or library.suffix.lower() == ".dll")
                }
                build = path.parent / "build.json"
                if build.is_file():
                    manifest[name]["build_manifest"] = {
                        "path": str(build),
                        "sha256": sha256(build),
                        "content": json.loads(build.read_text(encoding="utf-8")),
                    }
                for folder in (path.parent, path.parent.parent):
                    cache = folder / "CMakeCache.txt"
                    if cache.is_file():
                        manifest[name]["cmake_configuration"] = cmake_configuration(cache)
                        break
    manifest["library_inventory_scope"] = (
        "Canonical bytes of shared libraries beside each selected model executable. "
        "Repository build configurations are retained separately from executable identity."
    )
    manifest["repository_build_configurations"] = {
        str(cache.relative_to(repository)): cmake_configuration(cache)
        for cache in sorted((repository / ".runtime/llama-build").glob("*/CMakeCache.txt"))
    }
    manifest["native_source_sha256"] = {
        path.relative_to(repository).as_posix(): sha256(path)
        for folder in (
            "native/tn-llama/crates",
            "native/tn-llama/src",
            "native/tn-llama/include",
            "native/tn-llama/patches",
            "native/tn-llama/upstream/tn-proto/crypto",
        )
        for path in sorted((repository / folder).rglob("*"))
        if path.is_file()
        and "target" not in path.parts
        and path.suffix
        in {
            ".rs",
            ".c",
            ".cpp",
            ".h",
            ".hpp",
            ".patch",
            ".toml",
        }
    }
    manifest["build_input_sha256"] = {
        name: sha256(repository / name)
        for name in (
            "uv.lock",
            "pyproject.toml",
            "config/sdk-build.json",
            "native/tn-llama/Cargo.toml",
            "native/tn-llama/Cargo.lock",
            "native/tn-llama/upstream/tn-proto/Cargo.toml",
            "native/tn-llama/upstream/tn-proto/Cargo.lock",
            "native/tn-llama/source-manifest.json",
            "scripts/build_llama.sh",
            "scripts/build_plain_llama.sh",
            "scripts/package_llama.py",
        )
        if (repository / name).is_file()
    }
    native_module = native_module_path()
    manifest["native_sdk"] = {"path": str(native_module), "sha256": sha256(native_module)}
    manifest["runtime_versions"] = {
        "sqlite": sqlite3.sqlite_version,
        "openssl": ssl.OPENSSL_VERSION,
        "python_implementation": platform.python_implementation(),
    }
    rust_info = repository / ".runtime/llama-build/cargo-target/.rustc_info.json"
    if rust_info.is_file():
        info = json.loads(rust_info.read_text(encoding="utf-8"))
        manifest["rust_compiler_build_record"] = {
            "path": str(rust_info),
            "sha256": sha256(rust_info),
            "versions": [
                value["stdout"]
                for value in info.get("outputs", {}).values()
                if value.get("success") and value.get("stdout", "").startswith("rustc ")
            ],
        }
    return manifest


def validate_model_revision(version):
    match = re.search(r"\bcommit ([0-9a-f]{7,40})\b", version)
    if match is None or not "3f545beccee69d9975f466ec7e45fd9aacd8ba90".startswith(match[1]):
        raise ValueError("model server does not report the pinned llama.cpp revision")
    return match[1]


def preflight(args, profile):
    from tn_governed.native_run import wsl_command, wsl_path
    from tn_governed.values.model import digest

    from .performance_env import implementation_library, model_uses_wsl, native_module_path

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
        for name in ("binary", "plain_binary"):
            binary = getattr(args, name).resolve()
            command = (
                [*wsl_command(), wsl_path(binary), "--version"]
                if model_uses_wsl(binary)
                else [str(binary), "--version"]
            )
            completed = subprocess.run(
                command, check=True, capture_output=True, text=True, timeout=30
            )
            version = completed.stdout + completed.stderr
            validate_model_revision(version)
            result["model_versions"][name] = version
            implementation_library(binary)
    return result


def run_scale(root, args, profile):
    from .performance_model import ordinary_model_case
    from .processing_comparison import ordinary_case
    from .run import run_case

    cases, source_runs = [], {}
    requested_rows = list(
        dict.fromkeys(profile["rows"] + [profile["recipient_rows"], profile["tool_rows"]])
    )
    for repetition in range(-profile["warmups"], profile["repetitions"]):
        for rows in requested_rows:
            for mode in ("tn", "plain") if repetition % 2 == 0 else ("plain", "tn"):
                phase = "warmup" if repetition < 0 else "sample"
                name = f"rows-{rows}-{mode}-{phase}-{abs(repetition)}"
                directory = root / name
                print(name, flush=True)
                case = {
                    "rows": rows,
                    "mode": mode,
                    "repetition": repetition,
                    "warmup": repetition < 0,
                    "directory": str(directory),
                    "ok": False,
                    "seconds": None,
                }
                attempt_start = time.perf_counter()
                try:
                    with (
                        (root / f"{name}.log").open("w", encoding="utf-8") as log,
                        redirect_stdout(log),
                    ):
                        if mode == "tn":
                            summary = run_case(
                                directory,
                                "primitive",
                                rows=rows,
                                depth=1,
                                model=profile["model"],
                                unity_url=args.unity_url,
                                binary=args.binary,
                                model_path=args.model_path,
                                port=args.port,
                                storage="sqlite",
                                gpu_layers=0,
                                runtime_limits=profile.get("runtime_limits"),
                                sdk_build_record=getattr(args, "sdk_build_record", None),
                                sql_batch_size=profile.get("sql_batch_size", 64),
                            )
                        elif profile["model"]:
                            summary = ordinary_model_case(
                                directory,
                                rows,
                                binary=args.plain_binary,
                                model=args.model_path,
                                port=args.port,
                            )
                        else:
                            summary = ordinary_case(directory, rows)
                    case["summary"] = summary
                    case["ok"] = bool(summary["completed"] and summary["verified"])
                    if case["ok"]:
                        case["seconds"] = elapsed_processing(
                            summary["timings_seconds"], model=profile["model"]
                        )
                        case["content"] = summary["expected_content"]
                        if mode == "tn":
                            case["accounting"] = accounting(directory)
                            if case["accounting"]["direct_cell_refs"] != 2 * rows:
                                raise AssertionError("source reference count differs from workload")
                            if case["accounting"]["source_policies"] != 2:
                                raise AssertionError("source policy count differs from workload")
                            if repetition >= 0:
                                source_runs.setdefault(rows, directory)
                        peers = [c for c in cases if c["rows"] == rows and c["ok"]]
                        if any(c["content"] != case["content"] for c in peers):
                            raise AssertionError("plain and TN calculations differ")
                except Exception as exc:
                    case["ok"] = False
                    case["error_type"] = type(exc).__name__
                    (root / f"{name}.error.log").write_text(
                        traceback.format_exc(), encoding="utf-8"
                    )
                case["attempt_wall_seconds"] = time.perf_counter() - attempt_start
                cases.append(case)
                with (root / "samples.jsonl").open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(case, allow_nan=False) + "\n")
                save_json(
                    root / "scale.json", {"cases": cases, "aggregates": summarize_scale(cases)}
                )
                print(
                    json.dumps({k: case[k] for k in ("rows", "mode", "ok", "seconds")}), flush=True
                )
                if not case["ok"]:
                    raise RuntimeError(f"measurement failed; inspect {directory}")
    return cases, source_runs


def run_tool_workloads(root, args, profile):
    from .performance_tools import integrate_chain
    from .run import run_case

    root.mkdir(parents=True, exist_ok=False)
    cases = []
    for repetition in range(-profile["warmups"], profile["repetitions"]):
        for depth in profile["tool_depths"]:
            phase = "warmup" if repetition < 0 else "sample"
            name = f"depth-{depth}-{phase}-{abs(repetition)}"
            directory = root / name
            print(name, flush=True)

            def complete(context, report, brief, case_root, depth=depth):
                native_count = len(report.release.tool_objects) if report is not None else 0
                if native_count != int(profile["model"]):
                    raise AssertionError("native prerequisite count differs from the workload")
                additional = depth - native_count
                if additional:
                    completion = integrate_chain(
                        context, report, brief, additional, case_root / "tool-chain"
                    )
                else:
                    completion = {
                        "completed": True,
                        "verified": True,
                        "processing_seconds": 0,
                        "integrated_signed_records": 0,
                        "observed_depth": 0,
                    }
                if not completion.get("completed") or not completion.get("verified"):
                    completion["native_tool_count"] = native_count
                    return completion
                observed = completion["observed_depth"] + native_count
                if observed != depth:
                    raise AssertionError(
                        "observed application tool depth differs from requested depth"
                    )
                completion.update(native_tool_count=native_count, total_tool_depth=observed)
                return completion

            with (root / f"{name}.log").open("w", encoding="utf-8") as log, redirect_stdout(log):
                summary = run_case(
                    directory,
                    "primitive",
                    rows=profile["tool_rows"],
                    depth=1,
                    model=profile["model"],
                    unity_url=args.unity_url,
                    binary=args.binary,
                    model_path=args.model_path,
                    port=args.port,
                    storage="sqlite",
                    gpu_layers=0,
                    runtime_limits=profile.get("runtime_limits"),
                    sdk_build_record=getattr(args, "sdk_build_record", None),
                    sql_batch_size=profile.get("sql_batch_size", 64),
                    completion_handler=complete,
                )
            case = {
                "depth": depth,
                "warmup": repetition < 0,
                "repetition": repetition,
                "directory": str(directory),
                "summary": summary,
                "ok": bool(summary["completed"] and summary["verified"]),
            }
            if case["ok"]:
                case["end_to_end_seconds"] = elapsed_processing(
                    summary["timings_seconds"], model=profile["model"]
                )
                case["accounting"] = accounting(directory)
                case["signed_records"] = (
                    case["accounting"]["signed_context_records"]
                    + summary["completion"]["integrated_signed_records"]
                )
            cases.append(case)
            with (root / "samples.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(case, allow_nan=False) + "\n")
            if not case["ok"]:
                save_json(root / "results.json", {"completed": False, "cases": cases})
                raise RuntimeError(f"tool workload failed; inspect {directory}")
    aggregates = []
    for depth in profile["tool_depths"]:
        measured = [c for c in cases if c["depth"] == depth and not c["warmup"]]
        aggregates.append(
            {
                "depth": depth,
                "end_to_end_seconds": statistics_summary(
                    [c["end_to_end_seconds"] for c in measured]
                ),
                "signed_records": statistics_summary([c["signed_records"] for c in measured]),
                "tool_seconds": statistics_summary(
                    [c["summary"]["timings_seconds"]["tools"] for c in measured]
                ),
            }
        )
    baseline = next(
        (a["end_to_end_seconds"]["median"] for a in aggregates if a["depth"] == 1), None
    )
    for item in aggregates:
        item["overhead_vs_depth_1"] = (
            item["end_to_end_seconds"]["median"] / baseline if baseline else None
        )
    result = {
        "completed": True,
        "cases": cases,
        "aggregates": aggregates,
        "contract": "Each trial executes fresh SQL/Polars/scalar processing, one native model "
        "workflow when enabled, and the configured chain of dependent receipt tools. "
        "Depth counts the native compliance tool plus subsequent dependent receipt calls; "
        "section-selection and report-emission model "
        "turns are not application tool calls. "
        "End-to-end time sums active stages, excluding setup, model endpoint configuration, "
        "startup, "
        "offline verification and artifact export. Tool choices follow a fixed schedule.",
    }
    save_json(root / "results.json", result)
    return result


def main(argv=None):
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
    root = args.run_directory.resolve()
    root.mkdir(parents=True, exist_ok=False)
    manifest = environment_manifest(args, profile)
    save_json(root / "experiment.json", manifest)
    try:
        save_json(root / "preflight.json", {"completed": True, **preflight(args, profile)})
    except Exception as exc:
        save_json(root / "preflight.json", {"completed": False, "error_type": type(exc).__name__})
        raise
    if args.preflight_only:
        print(root / "experiment.json")
        return 0
    outcome = {"completed": False}
    try:
        cases, sources = run_scale(root, args, profile)
        from .performance_recipients import run_recipients

        outcome["scale"] = summarize_scale(cases)
        outcome["recipients"] = []
        for concurrency in profile["recipients"]:
            outcome["recipients"].append(
                run_recipients(
                    sources[profile["recipient_rows"]],
                    root / f"recipients-{concurrency}",
                    concurrency,
                    profile["recipient_repetitions"],
                    profile["warmups"],
                )
            )
        outcome["tools"] = run_tool_workloads(root / "tools", args, profile)
        outcome["completed"] = (
            all(r["status"] == "completed" for r in outcome["recipients"])
            and outcome["tools"]["completed"]
        )
    finally:
        save_json(root / "results.json", outcome)
    print(root / "results.json")
    return 0 if outcome["completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
