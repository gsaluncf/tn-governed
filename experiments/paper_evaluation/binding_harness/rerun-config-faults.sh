#!/bin/bash
# Rerun the fault study's configuration group on the clean round's code into its own directory.
set -uo pipefail
S=$(dirname "$(readlink -f "$0")")
bash "$S/binding-tree.sh" prepare 2>&1 | tail -1
T=$HOME/tn-cuda/binding/tn-governed
R=$HOME/tn-cuda/results/binding-r2/runtime-faults-configuration
cd "$T" || exit 1
cp .runtime/sdk-build-linux.json config/sdk-build.json
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:/usr/local/cuda/bin:/usr/lib/wsl/lib:/usr/bin:/bin"
export TN_POLARS_OPA=$T/.runtime/dependencies/opa POLARS_MAX_THREADS=16 PYTHONUNBUFFERED=1 PYTHONPATH=$T/src:$T
rm -rf "$R"
.venv/bin/python -m experiments.paper_evaluation.runtime_faults --run-directory "$R" --groups configuration \
    --unity-url http://127.0.0.1:18080 --binary .runtime/dependencies/tn-llama/llama-server \
    --fault-binary .runtime/dependencies/tn-llama-fault/llama-server \
    --plain-binary .runtime/llama-build/plain-cuda/bin/llama-server \
    --model-path "$HOME/tn-cuda/models/Qwen3-4B-Q4_K_M.gguf" --sdk-build-record .runtime/sdk-build-linux.json \
    --port 18345 --gpu-layers 99 > "$R.log" 2>&1
echo "exit $?"
python3 - "$R/configuration.json" <<'PY'
import json, sys
for name, case in json.load(open(sys.argv[1])).items():
    error = case.get("error") or {}
    print(f"{name}: {'released' if case.get('released') else 'refused ' + str(error.get('native_code') or error.get('type'))}")
PY
