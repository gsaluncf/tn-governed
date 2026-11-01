"""Measure independent recipient requests against one retained publication.

Each spawned process owns its native session, reader capability, local catalog,
evaluator and publication store. A request times handle hydration, verification,
local authorization, plaintext opening and durable signed disclosure records.
Enrollment, store copying, process startup and signed catalog admission are
excluded. Catalogs stay admitted across rounds; value verification and decisions
are repeated. Warmups are retained but excluded from reported statistics.

Round wall time starts before request dispatch and ends after
the parent receives every result, including synchronization and IPC overhead.
Throughput divides successful measured requests by summed measured round wall
time. Latency quantiles use successful requests; failed attempts remain visible.
"""

from __future__ import annotations

import json
import math
import multiprocessing
import os
import statistics
import time
from contextlib import suppress
from multiprocessing.connection import wait
from pathlib import Path

from .performance_source import open_recipient, prepare_recipients


def summarize_rounds(rounds):
    measured = [row for row in rounds if not row["warmup"]]
    requests = [request for row in measured for request in row["requests"]]
    successes = [request for request in requests if request["status"] == "completed"]
    timings = sorted(request["elapsed_ns"] / 1_000_000 for request in successes)
    wall_ns = sum(row["wall_ns"] for row in measured)
    return {
        "attempts": len(requests), "completed": len(successes),
        "failed": len(requests) - len(successes),
        "median_ms": statistics.median(timings) if timings else None,
        "p95_ms": timings[math.ceil(0.95 * len(timings)) - 1] if timings else None,
        "p95_method": "nearest rank over successful measured requests",
        "throughput_per_second": len(successes) * 1_000_000_000 / wall_ns if wall_ns else None,
        "measured_wall_ns": wall_ns,
    }


def _request(recipient):
    context, value = recipient["context"], recipient["value"]
    before = len(context.recorder.store.record_ids(context.recorder.context_id))
    started = time.perf_counter_ns()
    result = {"status": "failed", "error_type": None, "failure_stage": None}
    try:
        admitted = context.hydrate(value.reference, value.decision_id, value.result_id, kind="str")
        content = admitted.reveal(context, destination=recipient["destination"])
        if content != recipient["manifest"]["console_disclosures"]["internal"]:
            raise AssertionError("recipient content differs from the retained workload result")
        result["status"] = "completed"
    except Exception as error:
        result["error_type"] = type(error).__name__
        result["failure_stage"] = "request"
    finally:
        result["elapsed_ns"] = time.perf_counter_ns() - started
    ids = context.recorder.store.record_ids(context.recorder.context_id)[before:]
    result.update(
        signed_records=len(ids), record_ids=list(ids),
        identity=recipient["session"].did, pid=os.getpid(),
    )
    return result


def _worker(directory, connection, barrier):
    try:
        with open_recipient(directory) as recipient:
            connection.send({"status": "ready", "identity": recipient["session"].did,
                             "pid": os.getpid()})
            while True:
                command = connection.recv()
                if command == "close":
                    return
                if command != "request":
                    raise ValueError("unknown recipient worker command")
                barrier.wait(timeout=600)
                connection.send(_request(recipient))
    except EOFError:
        return
    except BaseException as error:
        with suppress(BrokenPipeError, EOFError, OSError):
            connection.send({"status": "failed", "error_type": type(error).__name__,
                             "pid": os.getpid(), "elapsed_ns": None, "failure_stage": "worker"})
        barrier.abort()
    finally:
        connection.close()


def _collect(connections, timeout):
    pending = set(connections)
    results = {}
    deadline = time.monotonic() + timeout
    while pending:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            for connection in pending:
                results[connection] = {
                    "status": "failed", "error_type": "TimeoutError",
                    "failure_stage": "worker_response", "elapsed_ns": None,
                }
            break
        for connection in wait(pending, timeout=remaining):
            try:
                results[connection] = connection.recv()
            except (EOFError, OSError) as error:
                results[connection] = {
                    "status": "failed", "error_type": type(error).__name__,
                    "failure_stage": "worker_response", "elapsed_ns": None,
                }
            pending.remove(connection)
    return [results[connection] for connection in connections]


def run_recipients(source_directory, output_directory, concurrency, repetitions, warmups):
    """Retain one process-isolated concurrency schedule and its raw requests."""
    for name, value, minimum in (
        ("concurrency", concurrency, 1), ("repetitions", repetitions, 1), ("warmups", warmups, 0)
    ):
        if type(value) is not int or value < minimum:
            raise ValueError(f"{name} must be an integer greater than or equal to {minimum}")
    root = Path(output_directory).resolve()
    root.mkdir(parents=True, exist_ok=False)
    result = {
        "schema": "tn.performance-recipients.v1", "status": "failed",
        "source_directory": str(Path(source_directory).resolve()),
        "concurrency": concurrency, "repetitions": repetitions, "warmups": warmups,
        "clock": "time.perf_counter_ns", "process_start_method": "spawn",
        "timed_operation": (
            "hydrate, verify lineage, authorize, open, record disclosure, compare content"
        ),
        "excluded_setup": "enrollment, store transfer, process startup, signed catalog admission",
        "cache_state": (
            "admitted local catalog; request-local value verification; no decision reuse"
        ),
        "round_wall_boundary": "before request dispatch through receipt of every worker result",
        "workers": [], "rounds": [], "error_type": None,
    }
    processes, connections = [], []
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(concurrency + 1)
    try:
        directories = prepare_recipients(source_directory, root / "endpoints", concurrency)
        manifest = json.loads((directories[0] / "run.json").read_text(encoding="utf-8"))
        result["source_rows"] = manifest.get("evaluation", {}).get("rows")
        result["source_object_id"] = manifest["outputs"]["model_input"]["reference"]["object_id"]
        for directory in directories:
            parent, child = context.Pipe()
            process = context.Process(target=_worker, args=(directory, child, barrier))
            process.start()
            child.close()
            processes.append(process)
            connections.append(parent)
        result["workers"] = _collect(connections, timeout=600)
        if any(worker["status"] != "ready" for worker in result["workers"]):
            raise RuntimeError("recipient preflight failed")
        if len({worker["identity"] for worker in result["workers"]}) != concurrency:
            raise RuntimeError("recipient identities are not distinct")
        with (root / "rounds.jsonl").open("x", encoding="utf-8") as raw:
            for index in range(warmups + repetitions):
                started = time.perf_counter_ns()
                synchronization_error = None
                try:
                    for connection in connections:
                        connection.send("request")
                    barrier.wait(timeout=600)
                except Exception as error:
                    synchronization_error = type(error).__name__
                    barrier.abort()
                requests = _collect(connections, timeout=2 if synchronization_error else 600)
                row = {
                    "round": index + 1, "warmup": index < warmups,
                    "wall_ns": time.perf_counter_ns() - started,
                    "requests": requests, "synchronization_error": synchronization_error,
                }
                result["rounds"].append(row)
                raw.write(json.dumps(row) + "\n")
                raw.flush()
                if synchronization_error or any(
                    request.get("failure_stage") in {"worker", "worker_response"}
                    for request in requests
                ):
                    raise RuntimeError("recipient worker round could not be completed")
        result["summary"] = summarize_rounds(result["rounds"])
        result["status"] = "completed" if all(
            request["status"] == "completed"
            for row in result["rounds"] for request in row["requests"]
        ) else "failed"
    except Exception as error:
        result["error_type"] = type(error).__name__
        result["summary"] = summarize_rounds(result["rounds"])
    finally:
        for connection in connections:
            with suppress(BrokenPipeError, EOFError, OSError):
                connection.send("close")
        for process in processes:
            process.join(timeout=2)
            if process.is_alive():
                process.terminate()
                process.join(timeout=2)
            if process.is_alive():
                process.kill()
                process.join(timeout=2)
        for connection in connections:
            connection.close()
        (root / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result
