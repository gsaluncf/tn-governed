#!/usr/bin/env bash
# Reuse the compiled inference engine while building the ordinary server route.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
build=.runtime/llama-build/cuda
test -f .runtime/dependencies/tn-llama/llama-server
cmake -S .runtime/llama-build/upstream -B "$build" -DLLAMA_TN_GOVERNED=OFF
cmake --build "$build" --target llama-server --parallel "${TN_BUILD_JOBS:-6}"
mkdir -p .runtime/llama-build/plain-cuda/bin
cp -a "$build/bin/". .runtime/llama-build/plain-cuda/bin/
