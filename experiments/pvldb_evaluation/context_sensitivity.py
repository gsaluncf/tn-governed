"""Governance context size and cost on the native model path.

Input rows set the number of provenance entries, which are listed in the model
context up to the presentation limit and replaced by committed references above
it. Additional attestations add signed claims, which always remain verbatim. The
retained server log gives prompt tokens and inference time for each case.
"""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

from tn_governed.native_run import ALL_GPU_LAYERS

from .evidence_mutants import native_rows
from .run import run_case
from .study_summary import log_turns

# The runtime lists at most LISTED_ENTRIES dataset bindings or lineage entries in
# the model context and replaces a longer list with its committed reference. Each
# BATCH input rows add two entries, so LISTED_ROWS is the largest fully listed input.
LISTED_ENTRIES = 16
BATCH = 256
LISTED_ROWS = LISTED_ENTRIES // 2 * BATCH
ROW_CASES = (8, BATCH, LISTED_ROWS // 2, LISTED_ROWS, LISTED_ROWS + BATCH, 2 * LISTED_ROWS, 8 * LISTED_ROWS)
CLAIM_CASES = (0, 1, 3, 7)
REFERENCE_SCHEMA = b"tn.governance-reference.v1"


def turn_timings(directory):
    """Inference over both model turns, the decrypt call and the report."""
    text = (directory / "native-model/server.stderr.log").read_text(encoding="utf-8", errors="replace")
    return log_turns(text)


def rendered_prompt(directory):
    trace = next((directory / "native-model/model-traces").glob("*.ndjson"))
    prepared = next(row for row in native_rows(trace) if row["kind"] == "turn_prepared")
    return base64.b64decode(prepared["rendered_prompt_b64"])


def measure(root, label, settings, *, rows, additional_claims=0, claim=True):
    directory = root / label
    summary = run_case(directory, "primitive", rows=rows, depth=1, model=True, claim=claim,
                       additional_claims=additional_claims, sql_batch_size=BATCH, storage="files",
                       **settings)
    if not (summary["completed"] and summary["verified"]):
        raise RuntimeError(f"context case failed: {label}: {summary.get('error')}")
    prompt = rendered_prompt(directory)
    return {"label": label, "rows": rows, "provenance_entries": 2 * -(-rows // BATCH),
            "provenance_listed": REFERENCE_SCHEMA not in prompt,
            "claims": (additional_claims + 1) if claim else 0,
            "rendered_prompt_bytes": len(prompt), **turn_timings(directory),
            "generation_seconds": summary["timings_seconds"]["generation"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-directory", type=Path, required=True)
    parser.add_argument("--unity-url", default="http://127.0.0.1:18080")
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--model-path", type=Path, required=True)
    parser.add_argument("--sdk-build-record", type=Path, required=True)
    parser.add_argument("--port", type=int, default=18365)
    parser.add_argument("--gpu-layers", type=int, default=ALL_GPU_LAYERS)
    args = parser.parse_args()
    root = args.run_directory.resolve()
    root.mkdir(parents=True, exist_ok=True)
    limits = json.loads(Path("config/performance.json").read_text(encoding="utf-8"))["runtime_limits"]
    settings = dict(unity_url=args.unity_url, binary=args.binary, model_path=args.model_path,
                    port=args.port, runtime_limits=limits, sdk_build_record=args.sdk_build_record,
                    gpu_layers=args.gpu_layers)
    results = [measure(root, f"rows-{rows}", settings, rows=rows) for rows in ROW_CASES]
    results.append(measure(root, "claims-0", settings, rows=8, claim=False))
    results += [measure(root, f"claims-{extra + 1}", settings, rows=8, additional_claims=extra)
                for extra in CLAIM_CASES[1:]]
    (root / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    listed = {item["rows"]: item["provenance_listed"] for item in results[:len(ROW_CASES)]}
    if not listed[LISTED_ROWS] or listed[LISTED_ROWS + BATCH]:
        raise RuntimeError(f"the runtime does not list exactly {LISTED_ENTRIES} provenance entries")


if __name__ == "__main__":
    raise SystemExit(main())
