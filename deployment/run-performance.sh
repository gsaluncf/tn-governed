#!/usr/bin/env bash
# Execute a benchmark batch from the unpacked runtime directory.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
servers=()
if [[ -f runtime/tn/llama-server ]]; then
    servers=(--binary "$root/runtime/tn/llama-server" --plain-binary "$root/runtime/plain/llama-server")
fi
runner=(-m experiments.paper_evaluation.performance)
if [[ -n "${TN_REMOTE_MODEL_CONFIG:-}" ]]; then
    runner=(deployment/remote_performance.py)
fi
exec .venv/bin/python "${runner[@]}" \
    --opa "$root/runtime/opa" --sdk-build-record "$root/.runtime/sdk-build-linux.json" \
    "${servers[@]}" "$@"
