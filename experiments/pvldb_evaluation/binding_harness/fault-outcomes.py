"""Tally a round's runtime fault outcomes per group (run in the evaluation environment; ROUND picks the round)."""
import collections
import json
import os
from pathlib import Path

ROOT = Path.home() / "tn-cuda/results" / os.environ.get("ROUND", "binding-r2")
GROUPS = ["control", "route", "configuration", "model-boundary", "prompt", "plain"]


def outcome(value):
    if not isinstance(value, dict):
        return type(value).__name__
    for key in ("outcome", "result", "status", "decision"):
        if key in value:
            return str(value[key])
    if "released" in value:
        state = "released" if value["released"] else "refused"
        if value["released"] and "notice_visible" in value:
            state += "-notice" if value["notice_visible"] else "-no-notice"
        if value["released"] and "verified" in value:
            state += "-verified" if value["verified"] else "-unverified"
        return state
    return "keys:" + ",".join(list(value)[:6])


def cases(group):
    path = ROOT / "runtime-faults" / f"{group}.json"
    if group == "configuration":
        path = ROOT / "runtime-faults-configuration" / "configuration.json"
    data = json.loads(path.read_text())
    if group == "route" and isinstance(data.get("route_probes"), (list, dict)):
        probes = data.pop("route_probes")
        probes = probes.values() if isinstance(probes, dict) else probes
        for index, probe in enumerate(probes):
            data[f"probe_{index}"] = probe
    return data


total = collections.Counter()
for group in GROUPS:
    data = cases(group)
    tally = collections.Counter(outcome(value) for value in data.values())
    total.update(tally)
    first = next(iter(data.values()))
    print(group, len(data), dict(tally))
    if isinstance(first, dict):
        print("   sample keys:", list(first)[:10])
print("all", sum(total.values()), dict(total))
