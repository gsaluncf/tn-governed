"""Repeat the report path to count how often the model presents the right hash keys.

Every run publishes fresh objects, so each decrypt turn shows the model new keys.
A wrong key ends the run with tn_decrypt_keys_invalid.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tn_governed.native_run import ALL_GPU_LAYERS

from .run import run_case


def outcome(index, rows, summary):
    error = summary.get("error") or {}
    return {"run": index, "rows": rows, "completed": summary["completed"],
            "verified": summary["verified"], "native_code": error.get("native_code"),
            "generation_seconds": summary["timings_seconds"].get("generation")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-directory", type=Path, required=True)
    parser.add_argument("--unity-url", default="http://127.0.0.1:18080")
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--model-path", type=Path, required=True)
    parser.add_argument("--sdk-build-record", type=Path, required=True)
    parser.add_argument("--port", type=int, default=18327)
    parser.add_argument("--gpu-layers", type=int, default=ALL_GPU_LAYERS)
    parser.add_argument("--runs", type=int, default=50)
    args = parser.parse_args()
    root = args.run_directory.resolve()
    root.mkdir(parents=True, exist_ok=True)
    outcomes = []
    for index in range(args.runs):
        rows = 8 + index
        summary = run_case(root / f"run-{index}", "primitive", rows=rows, depth=1, model=True,
                           unity_url=args.unity_url, binary=args.binary, model_path=args.model_path,
                           port=args.port, storage="files", gpu_layers=args.gpu_layers,
                           sdk_build_record=args.sdk_build_record)
        outcomes.append(outcome(index, rows, summary))
        (root / "results.json").write_text(json.dumps(outcomes, indent=2), encoding="utf-8")
    print(sum(item["completed"] for item in outcomes), "of", len(outcomes), "completed", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
