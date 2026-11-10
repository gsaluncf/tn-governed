#!/bin/bash
# Print a round's performance summary: scale aggregates, recipients, and tool depths.
R=$HOME/tn-cuda/results/${ROUND:-binding-r2}
python3 - "$R" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
summary = json.loads((root / "performance.json").read_text())
print("summary keys:", list(summary))
for item in summary["aggregates"]:
    keys = {k: v for k, v in item.items() if k not in ("rows", "mode")}
    print(item["rows"], item["mode"], json.dumps(keys, default=str)[:700])
results = json.loads((root / "performance/results.json").read_text())
print("\nscale:", json.dumps(results.get("scale"), default=str)[:900])
for item in results.get("recipients", []):
    print("\nrecipients:", json.dumps({k: v for k, v in item.items() if k not in ("rounds", "workers")}, default=str)[:600])
tools = results.get("tools", {})
for item in tools.get("aggregates", []):
    print("\ntools:", json.dumps(item, default=str)[:400])
PY
