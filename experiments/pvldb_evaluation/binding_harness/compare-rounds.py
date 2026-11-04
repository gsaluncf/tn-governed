"""Compare the pre-review evaluation round with the binding round, study by study.

usage: python3 compare-rounds.py BEFORE_DIR AFTER_DIR
"""
import json
import statistics
import sys
from collections import Counter
from pathlib import Path


def load(root, name):
    path = Path(root) / name
    return json.loads(path.read_text()) if path.is_file() else None


def both(name, before, after, render):
    print(f"\n## {name}")
    for label, root in (("before", before), ("after", after)):
        data = load(root, render[0])
        print(f"  {label}: " + ("pending" if data is None else render[1](data)))


def performance(data):
    parts = []
    for item in data["aggregates"]:
        seconds = item.get("processing_seconds") or {}
        parts.append(f"{item['rows']}/{item['mode']} median {seconds.get('median', 0):.2f}s")
    return "; ".join(parts)


def decrypt(data):
    good = [run for run in data if run["completed"] and run["verified"]]
    times = [run["generation_seconds"] for run in good]
    return f"{len(good)}/{len(data)} completed and verified; median generation {statistics.median(times):.2f}s"


def mutants(data):
    survived = sorted(name for name, item in data.items() if item.get("survived"))
    return f"{len(data) - len(survived)}/{len(data)} rejected; survivors {survived}"


def context(data):
    return "; ".join(f"{item['label']}: listed={item['provenance_listed']} prompt={item['prompt_tokens']} "
                     f"decoded={item['decoded_tokens']}" for item in data)


def publication(data):
    return "; ".join(f"{item['cells']} cells median {json.dumps(item['median'])[:80]}" for item in data)


def relation(data):
    return "; ".join(f"{item['workload']}/{item['query']}/{item['mode']} ratio {item['ratio']:.2f}"
                     for item in data["summary"])


def fault_outcomes(root):
    """Each fault case's outcome: released, or the refusal code that stopped it."""
    folder = Path(root) / "runtime-faults"
    outcomes = {}
    for path in sorted(folder.glob("*.json")) if folder.is_dir() else ():
        for name, case in json.loads(path.read_text()).items():
            if name == "route_probes":
                for probe in case:
                    outcomes[f"{path.stem}/{probe['fault']}"] = f"http {probe['status']} {probe.get('code')}"
                continue
            error = case.get("error") or {}
            refusal = error.get("native_code") or error.get("type") if isinstance(error, dict) else error
            outcomes[f"{path.stem}/{name}"] = "released" if case.get("released") else f"refused {refusal}"
    return outcomes


def faults(before, after):
    old, new = fault_outcomes(before), fault_outcomes(after)
    if not new:
        return "pending"
    tally = Counter(value.split(" ")[0] for value in new.values())
    changed = {name: (old.get(name), new.get(name)) for name in sorted(set(old) | set(new))
               if old.get(name) != new.get(name)}
    return f"{len(new)} cases {dict(tally)}; changed from before: {json.dumps(changed, indent=1)}"


def main(before, after):
    both("performance", before, after, ("performance.json", performance))
    both("decrypt reliability", before, after, ("decrypt-reliability/results.json", decrypt))
    both("propagation mutants", before, after, ("mutants/results.json", mutants))
    both("context sensitivity", before, after, ("context-sensitivity/results.json", context))
    both("publication size", before, after, ("publication-size/results.json", publication))
    both("relation market", before, after, ("relation-market/results.json", relation))
    both("relation tpch", before, after, ("relation-tpch/results.json", relation))
    print("\n## runtime faults")
    print("  " + faults(before, after))


if __name__ == "__main__":
    main(*sys.argv[1:3])
