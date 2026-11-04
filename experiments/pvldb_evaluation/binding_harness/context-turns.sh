#!/bin/bash
# Per-turn prompt and decode tokens for each context case, against the pre-review first-turn values;
# then the publication-size medians of both rounds side by side.
python3 - <<'PY'
import json, re
from pathlib import Path
home = Path.home() / "tn-cuda/results"
before = {item["label"]: item for item in json.loads((home / "final/context-sensitivity/results.json").read_text())}
after = json.loads((home / "binding-r1/context-sensitivity/results.json").read_text())
prompt = re.compile(r"\| task (\d+) \| prompt eval time =\s*([\d.]+) ms /\s*(\d+) tokens")
decode = re.compile(r"\| task (\d+) \|\s+eval time =\s*([\d.]+) ms /\s*(\d+) tokens")
print(f"{'case':12} {'turn1 now':>9} {'turn1 before':>12} {'turn2 now':>9} {'decoded now':>12} {'decoded before':>14} {'gen s now':>9} {'gen s before':>12}")
for item in after:
    log = (home / "binding-r1/context-sensitivity" / item["label"] / "native-model/server.stderr.log").read_text(errors="replace")
    prompts = [int(m[2]) for m in prompt.findall(log)]
    decodes = [int(m[2]) for m in decode.findall(log)]
    old = before.get(item["label"], {})
    print(f"{item['label']:12} {prompts[0] if prompts else '-':>9} {old.get('prompt_tokens', '-'):>12} "
          f"{prompts[1] if len(prompts) > 1 else '-':>9} {'+'.join(map(str, decodes)):>12} {old.get('decoded_tokens', '-'):>14} "
          f"{item['generation_seconds']:>9.2f} {old.get('generation_seconds', 0):>12.2f}")
print()
def table(name):
    return {item["cells"]: item["median"] for item in json.loads((home / name / "publication-size/results.json").read_text())}
old, new = table("final"), table("binding-r1")
for cells in sorted(new):
    parts = []
    for key in ("query", "dataframe", "verification", "cell_read", "retained_bytes", "files"):
        a, b = old[cells].get(key), new[cells].get(key)
        change = f"{(b - a) / a * 100:+.1f}%" if isinstance(a, (int, float)) and a else "n/a"
        parts.append(f"{key} {b:.3g} ({change})")
    print(f"{cells:5} cells: " + "; ".join(parts))
PY
