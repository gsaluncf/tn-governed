#!/usr/bin/env bash
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
backend="${1:-cpu}"
case "$backend" in cpu) cuda=OFF ;; cuda) cuda=ON ;; *) echo 'Usage: build_plain_llama.sh [cpu|cuda]' >&2; exit 2 ;; esac
cuda_options=()
if [[ "$cuda" == ON ]]; then
    cuda_options+=("-DCMAKE_CUDA_ARCHITECTURES=${TN_CUDA_ARCHITECTURES:-native}")
fi
source_dir="$root/.runtime/llama-build/upstream"
build_dir="$root/.runtime/llama-build/plain-$backend"
revision=3f545beccee69d9975f466ec7e45fd9aacd8ba90
[[ "$(git -C "$source_dir" rev-parse HEAD)" == "$revision" ]] || {
    echo 'Build the pinned TN server source with build_llama.sh first.' >&2; exit 1;
}
cmake -S "$source_dir" -B "$build_dir" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_BUILD_RPATH_USE_ORIGIN=ON \
    -DLLAMA_BUILD_SERVER=ON -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF \
    -DLLAMA_BUILD_TOOLS=ON -DLLAMA_BUILD_APP=OFF -DLLAMA_BUILD_UI=OFF \
    -DGGML_NATIVE=OFF -DGGML_CUDA="$cuda" "${cuda_options[@]}" -DLLAMA_TN_GOVERNED=OFF
cmake --build "$build_dir" --target llama-server --parallel "${TN_BUILD_JOBS:-4}"
