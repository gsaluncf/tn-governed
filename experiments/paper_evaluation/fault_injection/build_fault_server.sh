#!/usr/bin/env bash
# Build the evaluation server: the pinned TN llama.cpp integration plus the fault
# hooks in server-tn-faults.h. Output goes to .runtime/dependencies/tn-llama-fault
# and never replaces the packaged server.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)"
backend="${1:-cpu}"
jobs="${TN_BUILD_JOBS:-8}"
case "$backend" in cpu) cuda=OFF ;; cuda) cuda=ON ;; *) echo 'Usage: build_fault_server.sh [cpu|cuda]' >&2; exit 2 ;; esac
cuda_options=()
if [[ "$cuda" == ON ]]; then
    cuda_options+=("-DCMAKE_CUDA_ARCHITECTURES=${TN_CUDA_ARCHITECTURES:-native}")
fi
revision=3f545beccee69d9975f466ec7e45fd9aacd8ba90
source_root="$root/native/tn-llama"
work="$root/.runtime/llama-build"
upstream="$work/upstream-fault"
build="$work/fault-$backend"
python3 "$root/scripts/runtime_sources.py"
mkdir -p "$work"
if [[ ! -d "$upstream" ]]; then
    git init -q "$upstream"
    git -C "$upstream" remote add origin https://github.com/ggml-org/llama.cpp.git
    git -C "$upstream" fetch -q --depth 1 origin "$revision"
    git -C "$upstream" checkout -q --detach FETCH_HEAD
    git -C "$upstream" apply "$source_root/patches/llama.cpp/tn-governed-loop.patch"
fi
cp "$root/experiments/paper_evaluation/fault_injection/server-tn-faults.h" "$upstream/tools/server/"
python3 - "$upstream/tools/server/server-context.cpp" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
if "tn_fault_mutate_task" not in text:
    include = '#include "server-tn.h"\n'
    post = "    reader.post_task(std::move(task));\n    server_task_result_ptr result = reader.next(should_stop);\n"
    release = "    return {\n        final->id,\n        final->id_slot,\n"
    for marker in (include, post, release):
        if text.count(marker) != 1:
            raise SystemExit(f"expected one hook site: {marker!r}")
    text = text.replace(include, include + '#include "server-tn-faults.h"\n')
    text = text.replace(post, "    tn_fault_mutate_task(task);\n" + post)
    text = text.replace(release, "    tn_fault_mutate_result(*final);\n" + release)
    path.write_text(text, encoding="utf-8")
PY
export CARGO_TARGET_DIR="$work/cargo-target"
native_output=$(cargo rustc --manifest-path "$source_root/Cargo.toml" --locked --release -p tn-runtime --lib -j "$jobs" -- --print native-static-libs 2>&1)
native_libraries=$(printf '%s\n' "$native_output" | sed -n 's/.*native-static-libs: //p' | tail -1 | xargs | tr ' ' ';')
[[ -n "$native_libraries" ]] || { printf '%s\n' "$native_output" >&2; exit 1; }
cmake -S "$upstream" -B "$build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_BUILD_RPATH_USE_ORIGIN=ON \
    -DLLAMA_BUILD_SERVER=ON -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF \
    -DLLAMA_BUILD_TOOLS=ON -DLLAMA_BUILD_APP=OFF -DLLAMA_BUILD_UI=OFF \
    -DGGML_NATIVE=OFF -DGGML_CUDA="$cuda" "${cuda_options[@]}" \
    -DLLAMA_TN_GOVERNED=ON -DLLAMA_TN_PROJECT_ROOT="$source_root" \
    -DLLAMA_TN_RUNTIME_LIBRARY="$CARGO_TARGET_DIR/release/libtn_runtime.a" \
    -DLLAMA_TN_RUNTIME_NATIVE_LIBS="$native_libraries" >/dev/null
cmake --build "$build" --target llama-server --parallel "$jobs"
python3 "$root/scripts/package_llama.py" "$build/bin" "$root/.runtime/dependencies/tn-llama-fault" "$backend"
