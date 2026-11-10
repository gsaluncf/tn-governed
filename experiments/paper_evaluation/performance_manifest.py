"""The measurement environment: host, packages, sources, executables, and native build inputs."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from .performance_stats import PROCESS_STAGES

PACKAGES = ("tn-proto", "polars", "tn-polars", "tn-llama-client", "wasmtime")
PYTHON_SOURCES = ("experiments/paper_evaluation", "src/tn_governed", "dependencies/tn-polars/tn_polars")
NATIVE_SOURCES = (
    "native/tn-llama/crates",
    "native/tn-llama/src",
    "native/tn-llama/include",
    "native/tn-llama/patches",
    "native/tn-llama/upstream/tn-proto/crypto",
)
NATIVE_SUFFIXES = {".rs", ".c", ".cpp", ".h", ".hpp", ".patch", ".toml"}
BUILD_INPUTS = (
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
SELECTED_FILES = ("model_path", "binary", "plain_binary", "opa", "sdk_build_record")
MODEL_EXECUTABLES = {"binary", "plain_binary"}


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def environment_manifest(args, profile):
    import sqlite3
    import ssl

    from .performance_env import native_module_path

    repository = Path(__file__).resolve().parents[2]
    manifest = {
        "schema": "tn.performance.v1",
        "created_utc": datetime.now(UTC).isoformat(),
        "profile": profile,
        "command": sys.argv,
        **_host(),
        "packages": {package: importlib.metadata.version(package) for package in PACKAGES},
        "git_head": _git(repository, "rev-parse", "HEAD").strip(),
        "git_status": _git(repository, "status", "--short"),
        "source_sha256": _digests(repository, PYTHON_SOURCES, lambda path: path.suffix == ".py"),
        **_conventions(profile),
        "unity_url": args.unity_url,
        "services": {
            "wsl_distribution": os.environ.get("TN_WSL_DISTRO"),
            "polars_threads": os.environ.get("POLARS_MAX_THREADS"),
        },
    }
    if os.name == "nt":
        manifest.update(_windows_host())
    for name in SELECTED_FILES:
        if path := getattr(args, name, None):
            manifest[name] = _selected_file(name, path)
    native_module = native_module_path()
    manifest.update({
        "library_inventory_scope": (
            "Canonical bytes of shared libraries beside each selected model executable. "
            "Repository build configurations are retained separately from executable identity."
        ),
        "repository_build_configurations": {
            str(cache.relative_to(repository)): _cmake_configuration(cache)
            for cache in sorted((repository / ".runtime/llama-build").glob("*/CMakeCache.txt"))
        },
        "native_source_sha256": _digests(repository, NATIVE_SOURCES, _native_source),
        "build_input_sha256": {
            name: sha256(repository / name) for name in BUILD_INPUTS if (repository / name).is_file()
        },
        "native_sdk": {"path": str(native_module), "sha256": sha256(native_module)},
        "runtime_versions": {
            "sqlite": sqlite3.sqlite_version,
            "openssl": ssl.OPENSSL_VERSION,
            "python_implementation": platform.python_implementation(),
        },
    })
    if (rust := _rust_compiler(repository)) is not None:
        manifest["rust_compiler_build_record"] = rust
    return manifest


def _git(repository, *arguments):
    return subprocess.check_output(["git", *arguments], cwd=repository, text=True)


def _host():
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "logical_cpus": os.cpu_count(),
        "python": sys.version,
    }


def _digests(repository, folders, selected):
    return {
        path.relative_to(repository).as_posix(): sha256(path)
        for folder in folders
        for path in sorted((repository / folder).rglob("*"))
        if path.is_file() and selected(path)
    }


def _native_source(path):
    return "target" not in path.parts and path.suffix in NATIVE_SUFFIXES


def _conventions(profile):
    return {
        "clock": "time.perf_counter_ns / time.perf_counter; elapsed wall time",
        "latency_summary": "median and nearest-rank p95 of raw successful samples",
        "scale_timing": {
            "included": list(PROCESS_STAGES) + ["tools"],
            "reported_separately": ["generation"] if profile["model"] else [],
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
            "generation": "Reported separately, never in processing latency or the TN-to-plain "
            "ratio. TN: native protocol model turns, required tool, signed report, recipient "
            "acceptance and review queue registration. Plain: the request through the inspected "
            "report. Model inference inside it is split out by study_summary.cost_split.",
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
    }


def _windows_host():
    """Physical memory and CPU model from the Windows API and registry."""
    import ctypes
    import winreg

    class MemoryStatus(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ulong), ("load", ctypes.c_ulong)] + [
            (name, ctypes.c_ulonglong)
            for name in ("physical", "available", "page", "available_page", "virtual",
                         "available_virtual", "extended")
        ]

    facts = {}
    memory = MemoryStatus()
    memory.length = ctypes.sizeof(memory)
    if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)):
        facts["physical_memory_bytes"] = memory.physical
    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
    ) as key:
        facts["cpu_model"] = winreg.QueryValueEx(key, "ProcessorNameString")[0].strip()
    return facts


def _selected_file(name, path):
    """A selected file's identity; a model executable adds its libraries and build records."""
    path = path.resolve()
    facts = {"path": str(path), "sha256": sha256(path), "bytes": path.stat().st_size}
    if name not in MODEL_EXECUTABLES:
        return facts
    facts["adjacent_shared_libraries"] = {
        library.name: {"sha256": sha256(library), "bytes": library.stat().st_size}
        for library in sorted(path.parent.iterdir())
        if library.is_file() and (".so" in library.name or library.suffix.lower() == ".dll")
    }
    build = path.parent / "build.json"
    if build.is_file():
        facts["build_manifest"] = {
            "path": str(build),
            "sha256": sha256(build),
            "content": json.loads(build.read_text(encoding="utf-8")),
        }
    for folder in (path.parent, path.parent.parent):
        cache = folder / "CMakeCache.txt"
        if cache.is_file():
            facts["cmake_configuration"] = _cmake_configuration(cache)
            break
    return facts


def _cmake_configuration(cache):
    options = {}
    for line in cache.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith(("#", "//")) or "=" not in line or ":" not in line:
            continue
        typed_name, value = line.split("=", 1)
        name = typed_name.split(":", 1)[0]
        if name.startswith(("CMAKE_", "GGML_", "LLAMA_")) or name == "BUILD_SHARED_LIBS":
            options[name] = value
    return {
        "path": str(cache.resolve()),
        "sha256": sha256(cache),
        "options": options,
        "compiler_records": _compiler_records(cache),
    }


def _compiler_records(cache):
    compilers = {}
    for path in sorted(cache.parent.glob("CMakeFiles/*/CMake*Compiler.cmake")):
        values = dict(re.findall(
            r'set\((CMAKE_(?:C|CXX|CUDA)_COMPILER(?:_ID|_VERSION)?) "([^"]*)"\)',
            path.read_text(encoding="utf-8", errors="replace"),
        ))
        compilers[str(path.relative_to(cache.parent))] = {"sha256": sha256(path), "identity": values}
    return compilers


def _rust_compiler(repository):
    rust_info = repository / ".runtime/llama-build/cargo-target/.rustc_info.json"
    if not rust_info.is_file():
        return None
    info = json.loads(rust_info.read_text(encoding="utf-8"))
    return {
        "path": str(rust_info),
        "sha256": sha256(rust_info),
        "versions": [
            value["stdout"]
            for value in info.get("outputs", {}).values()
            if value.get("success") and value.get("stdout", "").startswith("rustc ")
        ],
    }
