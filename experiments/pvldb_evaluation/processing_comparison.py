"""Compare ordinary SQL/Polars processing with two governed scalar interfaces."""

import argparse
import hashlib
import json
import platform
import sqlite3
import statistics
import subprocess
import time
from collections import defaultdict
from contextlib import closing, redirect_stdout
from datetime import UTC, datetime
from pathlib import Path

import polars as pl

from tn_governed.publications import open_publication_store

from .run import run_case

PROCESS_STAGES = ("query", "claim", "dataframe", "compute", "console_disclosure")
MODES = ("ordinary", "primitive", "explicit")


def ordinary_case(directory, rows):
    directory.mkdir(parents=True, exist_ok=False)
    started = time.perf_counter()
    database = directory / "market.sqlite"
    with closing(sqlite3.connect(database)) as connection:
        connection.execute("CREATE TABLE market_data (name TEXT NOT NULL, value INTEGER NOT NULL)")
        connection.executemany(
            "INSERT INTO market_data VALUES (?, ?)",
            [("ACME" if i == 0 else f"ACME-{i}", 1250 + i) for i in range(rows)],
        )
        connection.commit()
    timings = {"setup": time.perf_counter() - started}
    start = time.perf_counter()
    with closing(sqlite3.connect(database)) as connection:
        fetched = connection.execute(
            "SELECT name, value FROM market_data LIMIT ?", (rows,)
        ).fetchall()
    timings["query"] = time.perf_counter() - start
    start = time.perf_counter()
    frame = pl.DataFrame(
        fetched, schema={"name": pl.String, "value": pl.Int64}, orient="row"
    ).lazy()
    result = (
        frame.filter(pl.col("value") >= 0)
        .sort("name")
        .with_columns((pl.col("value") + 250).alias("adjusted"))
    )
    amount = result.select(pl.col("adjusted").sum().alias("amount")).collect().item()
    timings["dataframe"] = time.perf_counter() - start
    start = time.perf_counter()
    amount = amount + 1
    brief = fetched[0][0].upper() + ": " + str(amount) + " demonstration cents"
    timings["compute"] = time.perf_counter() - start
    expected_amount = sum(v + 250 for _, v in fetched if v >= 0) + 1
    expected = f"{fetched[0][0].upper()}: {expected_amount} demonstration cents"
    if len(fetched) != rows or brief != expected:
        raise AssertionError("ordinary calculation differs from the SQL input calculation")
    (directory / "result.txt").write_text(brief, encoding="utf-8")
    timings["total"] = time.perf_counter() - started
    return {
        "completed": True,
        "verified": True,
        "timings_seconds": timings,
        "expected_content": brief,
        "output_publication_bytes": None,
    }


def summarize(cases):
    groups = defaultdict(list)
    for case in cases:
        groups[(case["rows"], case["mode"])].append(case)
    summaries = []
    for (rows, mode), group in sorted(groups.items()):
        item = {"rows": rows, "mode": mode, "repetitions": len(group)}
        for name in (
            "processing_seconds",
            "verification_seconds",
            "setup_seconds",
            "export_and_other_seconds",
            "total_seconds",
            "output_publication_bytes",
        ):
            values = [case[name] for case in group if case[name] is not None]
            item[name] = (
                {"median": statistics.median(values), "min": min(values), "max": max(values)}
                if values
                else None
            )
        summaries.append(item)
    return summaries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-directory", type=Path, required=True)
    parser.add_argument("--rows", nargs="+", type=int, default=[128, 512, 1024])
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--unity-url", default="http://127.0.0.1:8080")
    args = parser.parse_args()
    if min(args.rows) < 1 or args.repetitions < 1:
        raise ValueError("row and repetition counts must be positive")
    root = args.run_directory.resolve()
    root.mkdir(parents=True, exist_ok=False)
    schedule = [
        (repetition + 1, rows, mode)
        for repetition in range(args.repetitions)
        for rows in args.rows
        for mode in MODES[repetition % 3 :] + MODES[: repetition % 3]
    ]
    repository = Path(__file__).resolve().parents[2]
    manifest = {
        "created_utc": datetime.now(UTC).isoformat(),
        "command": subprocess.list2cmdline(__import__("sys").argv),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "git_head": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repository, text=True
        ).strip(),
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "schedule": schedule,
        "processing_stages": list(PROCESS_STAGES),
        "scope": (
            "Same integer inputs, SQL query, Polars plan, scalar increment and string composition. "
            "Governed modes share SQL/dataframe controls and differ only in scalar dispatch. "
            "Setup and exported verification records are reported separately. Ordinary processing "
            "has no governed publication or offline governance verification."
        ),
        "warmup": (
            "One ordinary 128-row calculation initializes Polars before timed repetitions. "
            "Unity is running before the experiment. "
            "Governed cases use fresh sessions and storage; "
            "each case retains the production evaluator compilation and caches."
        ),
    }
    (root / "experiment.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    ordinary_case(root / "warmup", 128)
    cases = []
    for repetition, rows, mode in schedule:
        name = f"rows-{rows}-{mode}-repeat-{repetition}"
        directory = root / name
        print(f"{len(cases) + 1}/{len(schedule)} {name}", flush=True)
        if mode == "ordinary":
            result = ordinary_case(directory, rows)
            output_bytes = None
        else:
            with (root / (name + ".log")).open("w", encoding="utf-8") as log, redirect_stdout(log):
                result = run_case(
                    directory,
                    mode,
                    rows=rows,
                    depth=1,
                    branches=1,
                    model=False,
                    claim=True,
                    unity_url=args.unity_url,
                    storage="files",
                )
            if not result["completed"] or not result["verified"]:
                raise RuntimeError(f"governed execution failed; inspect {directory}")
            run = json.loads((directory / "run.json").read_text())
            identity = run["outputs"]["model_input"]["reference"]["object_id"]
            with open_publication_store(directory / "publications", read_only=True) as store:
                output_bytes = len(store.get(identity))
        timing = result["timings_seconds"]
        processing = sum(timing.get(stage, 0) for stage in PROCESS_STAGES)
        verification = timing.get("verification")
        setup = timing.get("setup", 0) + timing.get("assignment", 0)
        case = {
            "rows": rows,
            "mode": mode,
            "repetition": repetition,
            "processing_seconds": processing,
            "verification_seconds": verification,
            "setup_seconds": setup,
            "export_and_other_seconds": timing["total"] - processing - (verification or 0) - setup,
            "total_seconds": timing["total"],
            "output_publication_bytes": output_bytes,
            "result": result["expected_content"],
            "timings_seconds": timing,
            "directory": str(directory),
        }
        if any(prior["result"] != case["result"] for prior in cases if prior["rows"] == rows):
            raise AssertionError("comparison modes produced different results")
        cases.append(case)
        output = {"cases": cases, "aggregates": summarize(cases)}
        (root / "measurements.json").write_text(json.dumps(output, indent=2), encoding="utf-8")
        print(
            json.dumps(
                {
                    k: case[k]
                    for k in (
                        "mode",
                        "rows",
                        "processing_seconds",
                        "verification_seconds",
                        "total_seconds",
                    )
                }
            ),
            flush=True,
        )


if __name__ == "__main__":
    main()
