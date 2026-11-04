"""Publication size: the data path against the cost of reading one cell.

A source publication plays the part of a Parquet row group. One signed Result,
one edition and one admission cover all its cells, and opening any cell decrypts
the whole group. Larger publications cut the per-publication work of a scan and
raise the cost of a read that touches few cells.
"""

from __future__ import annotations

import argparse
import json
import shutil
import statistics
from pathlib import Path

from .run import run_case

CELL_READS = 8
RETAINED = ("publications", "tapes", "editions")
# Dataset bindings one governed object may carry; the result binds every source edition.
MAX_BINDINGS = 1024


def editions(rows, size):
    """Source editions of the primitive workload: one per column, two columns, per batch of rows."""
    return 2 * -(-rows // size)


def retained_bytes(root):
    return sum(path.stat().st_size for name in RETAINED
               for path in (root / name).rglob("*") if path.is_file())


def measure(root, *, rows, size, unity_url, sdk_build_record):
    summary = run_case(root, "primitive", rows=rows, unity_url=unity_url, storage="files",
                       sql_batch_size=size, sdk_build_record=sdk_build_record,
                       cell_reads=CELL_READS)
    if not summary["completed"] or not summary["verified"]:
        raise RuntimeError(f"case at {size} cells did not complete: {summary['error']}")
    timings = summary["timings_seconds"]
    return {"query": timings["query"], "dataframe": timings["dataframe"],
            "verification": timings["verification"], "cell_read": timings["cell_read"] / CELL_READS,
            "retained_bytes": retained_bytes(root),
            "files": sum(1 for path in root.rglob("*") if path.is_file())}


def summarize(runs):
    return {name: statistics.median(run[name] for run in runs) for name in runs[0]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-directory", type=Path, required=True)
    parser.add_argument("--rows", type=int, default=100000)
    parser.add_argument("--sizes", type=int, nargs="+", default=[256, 512, 1024, 2048, 4096])
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--unity-url", default="http://127.0.0.1:18080")
    parser.add_argument("--sdk-build-record", type=Path)
    args = parser.parse_args()
    infeasible = [size for size in args.sizes if editions(args.rows, size) > MAX_BINDINGS]
    if infeasible:
        parser.error(f"sizes {infeasible} need more than {MAX_BINDINGS} dataset bindings at {args.rows} rows")
    args.run_directory.mkdir(parents=True, exist_ok=True)
    results = []
    for size in args.sizes:
        runs = []
        for repetition in range(args.repetitions):
            root = args.run_directory / f"cells-{size}-{repetition}"
            runs.append(measure(root, rows=args.rows, size=size, unity_url=args.unity_url,
                                sdk_build_record=args.sdk_build_record))
            shutil.rmtree(root)
        results.append({"cells": size, "rows": args.rows, "repetitions": args.repetitions,
                        "runs": runs, "median": summarize(runs)})
        (args.run_directory / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(json.dumps([{"cells": item["cells"], **item["median"]} for item in results], indent=2))


if __name__ == "__main__":
    main()
