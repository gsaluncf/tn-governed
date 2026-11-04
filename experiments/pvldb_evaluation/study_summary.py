"""Reduce a retained performance run to one auditable JSON document.

Each case keeps its stage timers, model tokens from the server log, the native
turn timeline from the audit log, accounting, and peak resident memory. Aggregates
report the median, minimum, and maximum of measured samples; warmups stay in the
case list and are excluded from aggregates.

Model inference (prompt evaluation and decoding in the server log) depends on the
model and GPU rather than on TN, so it is reported apart from TN work: the data
stages plus everything else in the generation stage.
"""

from __future__ import annotations

import argparse
import json
import re
import statistics
from datetime import datetime
from pathlib import Path

STAGES = ("query", "claim", "dataframe", "compute", "console_disclosure", "generation")
DATA_STAGES = STAGES[:-1]
COSTS = ("data_seconds", "runtime_seconds", "work_seconds", "inference_seconds")


def _instant(text):
    whole, _, fraction = text.rstrip("Z").partition(".")
    return datetime.fromisoformat(whole).timestamp() + float("0." + (fraction or "0"))


def native_timeline(directory):
    """Separate native runtime work from inference using the audit timestamps."""
    path = Path(directory) / "native-model/model-audit.ndjson"
    if not path.is_file():
        return None
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    stamps = {}
    for row in rows:
        stamps.setdefault(row["kind"], []).append(_instant(row["timestamp"]))
    first, last = _instant(rows[0]["timestamp"]), _instant(rows[-1]["timestamp"])
    begun = stamps["turn_begin_authorized"]
    decrypted, emitted = stamps["sections_selected"][0], stamps["output_emitted_and_read_back"][0]
    return {"admission_to_turn_seconds": begun[0] - first, "decrypt_turn_seconds": decrypted - begun[0],
            "decrypt_to_turn_seconds": begun[-1] - decrypted, "report_turn_seconds": emitted - begun[-1],
            "release_seconds": last - emitted, "audit_kinds": [row["kind"] for row in rows]}


def model_turns(directory):
    path = Path(directory) / "native-model/server.stderr.log"
    if not path.is_file():
        path = Path(directory) / "server.stderr.log"
    if not path.is_file():
        return None
    return log_turns(path.read_text(encoding="utf-8", errors="replace"))


def log_turns(text):
    """Prompt and decode time and tokens in a llama-server log, summed over every turn."""
    prompts = re.findall(r"prompt eval time =\s*([\d.]+) ms /\s*(\d+) tokens", text)
    decodes = re.findall(r"\|\s+eval time =\s*([\d.]+) ms /\s*(\d+) tokens", text)
    return {"inferences": len(prompts),
            "prompt_tokens": sum(int(tokens) for _, tokens in prompts),
            "prompt_seconds": sum(float(ms) for ms, _ in prompts) / 1000,
            "decoded_tokens": sum(int(tokens) for _, tokens in decodes),
            "decode_seconds": sum(float(ms) for ms, _ in decodes) / 1000}


def plain_turns(case):
    usage = case.get("summary", {}).get("model_usage") or {}
    timing = case.get("summary", {}).get("model_timings") or {}
    if not timing:
        return None
    return {"inferences": 1, "prompt_tokens": usage.get("prompt_tokens"),
            "prompt_seconds": timing.get("prompt_ms", 0) / 1000,
            "decoded_tokens": usage.get("completion_tokens"),
            "decode_seconds": timing.get("predicted_ms", 0) / 1000}


def cost_split(timings, turns):
    """TN work and model inference, kept apart."""
    data = sum(timings.get(name) or 0 for name in DATA_STAGES)
    inference = (turns["prompt_seconds"] + turns["decode_seconds"]) if turns else 0.0
    runtime = (timings.get("generation") or 0) + (timings.get("tools") or 0) - inference
    return {"data_seconds": data, "runtime_seconds": runtime, "work_seconds": data + runtime,
            "inference_seconds": inference}


def reduce_case(case):
    summary = case.get("summary", {})
    timings = summary.get("timings_seconds", {})
    directory = Path(case["directory"])
    turns = (case.get("model_turns") or model_turns(directory)) if case["mode"] == "tn" else plain_turns(case)
    return {
        "rows": case["rows"], "mode": case["mode"], "repetition": case["repetition"],
        "warmup": case["warmup"], "ok": case["ok"], "processing_seconds": case["seconds"],
        "stages": {name: timings.get(name) for name in (*STAGES, "native_prepare", "server_start",
                                                        "export", "verification")},
        "accounting": {k: v for k, v in case.get("accounting", {}).items()
                       if k != "source_policy_refs"},
        "model": turns,
        "cost": cost_split(timings, turns),
        "native_timeline": ((case.get("native_timeline") or native_timeline(directory))
                            if case["mode"] == "tn" else None),
        "peak_rss_bytes": case.get("peak_rss_bytes"),
        "verification": {k: v for k, v in summary.get("verification", {}).items()
                         if k in ("record_count", "incarnations", "derivation_edges")},
    }


def spread(values):
    values = [value for value in values if value is not None]
    if not values:
        return None
    return {"n": len(values), "median": statistics.median(values), "min": min(values),
            "max": max(values)}


def nested(cases, *path):
    for case in cases:
        value = case
        for key in path:
            value = value.get(key) if isinstance(value, dict) else None
        yield value


def aggregate(cases):
    results = []
    for rows in sorted({case["rows"] for case in cases}):
        for mode in ("tn", "plain"):
            selected = [c for c in cases if c["rows"] == rows and c["mode"] == mode
                        and not c["warmup"] and c["ok"]]
            if not selected:
                continue
            item = {"rows": rows, "mode": mode,
                    "processing_seconds": spread(c["processing_seconds"] for c in selected),
                    "peak_rss_bytes": spread(c["peak_rss_bytes"] for c in selected)}
            for name in (*STAGES, "export", "verification", "native_prepare"):
                item[name] = spread(nested(selected, "stages", name))
            for name in COSTS:
                item[name] = spread(nested(selected, "cost", name))
            for name in ("prompt_tokens", "prompt_seconds", "decoded_tokens", "decode_seconds", "inferences"):
                item["model_" + name] = spread(nested(selected, "model", name))
            for name in ("admission_to_turn_seconds", "decrypt_turn_seconds", "decrypt_to_turn_seconds",
                         "report_turn_seconds", "release_seconds"):
                item[name] = spread(nested(selected, "native_timeline", name))
            for name in ("signed_context_records", "scalar_publication_bytes", "retained_native_bytes",
                         "direct_cell_refs", "retained_native_objects"):
                item[name] = spread(nested(selected, "accounting", name))
            results.append(item)
    return results


def read_samples(path):
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def recipients(root):
    results = []
    for path in sorted(root.glob("recipients-*/result.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        results.append({**{key: item for key, item in value.items()
                           if not isinstance(item, (list, dict))}, **value.get("summary", {})})
    return results


def tool_depth(root):
    path = root / "tools/results.json"
    if not path.is_file():
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    return {"aggregates": value.get("aggregates"), "contract": value.get("contract")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_directory", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.run_directory.resolve()
    experiment = json.loads((root / "experiment.json").read_text(encoding="utf-8"))
    cases = [reduce_case(case) for case in read_samples(root / "samples.jsonl")]
    document = {
        "schema": "tn.performance-study-summary.v1", "run": root.name,
        "profile": experiment["profile"], "platform": experiment["platform"],
        "processor": experiment.get("processor"), "logical_cpus": experiment.get("logical_cpus"),
        "packages": experiment["packages"], "git_head": experiment["git_head"],
        "git_status": experiment["git_status"], "created_utc": experiment["created_utc"],
        "aggregates": aggregate(cases), "recipients": recipients(root), "tool_depth": tool_depth(root),
        "cases": cases,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
