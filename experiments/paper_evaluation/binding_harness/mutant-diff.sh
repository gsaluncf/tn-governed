#!/bin/bash
# Compare each mutant's outcome between the pre-review and binding rounds.
python3 - <<'PY'
import json
from pathlib import Path
home = Path.home() / "tn-cuda/results"
before = json.loads((home / "final/mutants/results.json").read_text())
after = json.loads((home / "binding-r1/mutants/results.json").read_text())
def outcome(item):
    if item.get("survived"):
        return "survived"
    if item.get("runtime_error"):
        error = item["runtime_error"]
        return "runtime " + (error.get("type", "") if isinstance(error, dict) else str(error))[:40]
    if not item.get("workload_check", True) and item.get("verifier_rejection") is None:
        return "workload check"
    return "verifier " + (item.get("verifier_rejection") or "")[:90]
families = {}
for name in sorted(set(before) | set(after)):
    old, new = before.get(name), after.get(name)
    families.setdefault((new or old)["family"], []).append(name)
    a, b = outcome(old) if old else "absent", outcome(new) if new else "absent"
    if a.split(":")[0] != b.split(":")[0]:
        print(f"CHANGED {name}:\n   before {a}\n   after  {b}")
print({family: len(names) for family, names in families.items()})
kinds = {}
for item in after.values():
    kinds[outcome(item).split(" ")[0]] = kinds.get(outcome(item).split(" ")[0], 0) + 1
print("after outcomes:", kinds)
PY
ls -la --time-style=+%H:%M:%S ~/tn-cuda/results/binding-r1/mutants | head -5
