#!/bin/bash
# The clean round's headline numbers: scale ratios, generation, peak memory, recipients, and tool depths.
python3 - <<'PY'
import json
from pathlib import Path
root = Path.home() / "tn-cuda/results/binding-r2"
summary = json.loads((root / "performance.json").read_text())
results = json.loads((root / "performance/results.json").read_text())
med = lambda value: (value or {}).get("median")
for item in summary["aggregates"]:
    stages = {k: med(item.get(k)) for k in ("query", "claim", "dataframe", "compute", "console_disclosure", "generation")}
    print(item["rows"], item["mode"], "processing", f"{med(item['processing_seconds']):.4f}",
          "peak GB", f"{med(item['peak_rss_bytes']) / 1e9:.2f}",
          {k: round(v, 4) for k, v in stages.items() if v is not None})
for item in results["scale"]:
    print("ratio", item["rows"], round(item["tn_plain_ratio"], 1), "failures", item["tn"]["failures"], item["plain"]["failures"])
for item in summary.get("recipients") or []:
    print("recipients", json.dumps(item, default=str)[:300])
for item in results["tools"]["aggregates"]:
    print("tools depth", item["depth"], "end to end", round(item["end_to_end_seconds"]["median"], 3),
          "records", item["signed_records"]["median"], "tool s", round(item["tool_seconds"]["median"], 3),
          "overhead", round(item["overhead_vs_depth_1"], 2))
PY
