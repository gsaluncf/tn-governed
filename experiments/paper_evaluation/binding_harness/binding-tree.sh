#!/bin/bash
# The binding evaluation harness in WSL 2, built from the binding checkouts.
# usage: binding-tree.sh prepare|venv|sdk|native|smoke [rows]
set -uo pipefail
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:/usr/local/cuda/bin:/usr/lib/wsl/lib:/usr/bin:/bin"
W=${BINDING_SOURCES:?set BINDING_SOURCES to the directory that holds the three binding checkouts}
B=$HOME/tn-cuda/binding
G=$B/tn-governed
N=$G/native/tn-llama
P=$B/tn-proto
OLD=$HOME/tn-cuda/tn-governed
VENDORED=${VENDORED_NATIVE:?set VENDORED_NATIVE to the native/tn-llama of a tn-governed checkout}
EXCLUDES=(--exclude .venv --exclude /.runtime --exclude experiments/results --exclude __pycache__
          --exclude target --exclude .git --exclude .pytest_cache --exclude .ruff_cache --exclude /native)

prepare() {
    mkdir -p "$G" "$N/upstream/tn-proto/crypto" "$P"
    rsync -a --delete "${EXCLUDES[@]}" "$W/tn-governed-binding/" "$G/"
    rsync -a --delete --exclude target "$W/tn-llama-binding/crates/" "$N/crates/"
    cp "$W/tn-llama-binding/Cargo.toml" "$W/tn-llama-binding/Cargo.lock" "$N/"
    rsync -a --delete "$VENDORED/patches/" "$N/patches/"
    rsync -a --delete "$VENDORED/include/" "$N/include/"
    rsync -a --delete "$VENDORED/src/" "$N/src/"
    rsync -a --delete "$W/tn-llama-binding/demo/" "$N/demo/"
    for crate in tn-core tn-btn tn-hibe tn-bbg; do
        rsync -a --delete --exclude target "$W/tn-proto-binding/crypto/$crate/" "$N/upstream/tn-proto/crypto/$crate/"
    done
    cp "$VENDORED/upstream/tn-proto/Cargo.toml" "$N/upstream/tn-proto/Cargo.toml"
    sed -i 's#\.\./\.\./\.\./tn-proto-binding/crypto/#../../upstream/tn-proto/crypto/#' \
        "$N/crates/tn-runtime/Cargo.toml" "$N/crates/tn-test-tools/Cargo.toml"
    grep -h 'path = ' "$N/crates/tn-runtime/Cargo.toml" "$N/crates/tn-test-tools/Cargo.toml"
    cp "$VENDORED/source-manifest.json" "$N/source-manifest.json"
    python3 "$(dirname "$(readlink -f "$0")")/native_manifest.py" "$N" \
        "${PROTO_COMMIT:-unrecorded}" "${LLAMA_COMMIT:-unrecorded}"
    (cd "$G" && python3 scripts/runtime_sources.py)
    for tree in crypto python rust-sdk; do
        rsync -a --delete --exclude target --exclude dist --exclude __pycache__ --exclude '*.pyd' --exclude '*.so' \
            "$W/tn-proto-binding/$tree/" "$P/$tree/"
    done
    cp "$W/tn-proto-binding/Cargo.toml" "$W/tn-proto-binding/Cargo.lock" "$P/"
    mkdir -p "$G/.runtime/dependencies"
    cp "$OLD/.runtime/dependencies/opa" "$G/.runtime/dependencies/opa"
    du -sh "$B"
}

venv() {
    cd "$G" || exit 1
    [ -x .venv/bin/python ] || python3.12 -m venv .venv
    .venv/bin/python -m pip install -q uv maturin
    UV=.venv/bin/uv
    $UV export --frozen --no-hashes --no-emit-project --extra dev \
        | grep -vE '^(tn-proto|tn-polars|tn-llama-client|\./|-e |#|    #)' | grep -v 'vendor/wheels' > .venv/requirements.txt
    $UV pip install -q --no-config --python .venv/bin/python --no-deps -r .venv/requirements.txt
    $UV pip install -q --no-config --python .venv/bin/python --no-deps \
        -e dependencies/tn-polars -e dependencies/tn-llama-client -e .
    .venv/bin/python -c "import polars, tn_polars; print('venv ok', polars.__version__)"
}

sdk() {
    export PYO3_PYTHON=$G/.venv/bin/python
    rm -rf "$P/dist"
    cd "$P/python" || exit 1
    time "$G/.venv/bin/maturin" build --release --interpreter "$PYO3_PYTHON" --out "$P/dist" 2>&1 | tail -4
    built=$(ls "$P"/dist/tn_proto-*.whl) || exit 1
    sha=$(sha256sum "$built" | cut -d' ' -f1)
    mkdir -p "$G/vendor/wheels/$sha"
    wheel="$G/vendor/wheels/$sha/$(basename "$built")"
    cp "$built" "$wheel"
    "$G/.venv/bin/uv" pip install -q --no-config --python "$PYO3_PYTHON" --no-deps --reinstall "$wheel" || exit 1
    cd "$G" || exit 1
    "$PYO3_PYTHON" - "$wheel" <<'PY'
import hashlib
import importlib.metadata
import json
import sys
from pathlib import Path

import tn._native as native

digest = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
Path(".runtime/sdk-build-linux.json").write_text(json.dumps({
    "distribution": "tn-proto", "version": importlib.metadata.version("tn-proto"),
    "wheel_sha256": digest(sys.argv[1]),
    "install": {"native_module_sha256": digest(native.__file__)},
}, indent=2), encoding="utf-8")
print(Path(".runtime/sdk-build-linux.json").read_text())
PY
}

native() {
    cd "$G" || exit 1
    # Reuse the evaluated llama.cpp checkout and CUDA objects; only the Rust runtime changed.
    [ -e .runtime/llama-build ] || ln -s "$OLD/.runtime/llama-build" .runtime/llama-build
    export TN_BUILD_JOBS=14 TN_CUDA_ARCHITECTURES=86
    time bash scripts/build_llama.sh cuda 2>&1 | grep -vE '^\s+(Compiling|Downloaded|Downloading)' | tail -25
    ldd .runtime/dependencies/tn-llama/llama-server | grep -iE 'cuda|ggml|not found' || true
    ls -la .runtime/dependencies/tn-llama/llama-server
}

smoke() {
    rows=${1:-8}
    R=$HOME/tn-cuda/results/binding-smoke-$rows
    rm -rf "$R"
    cd "$G" || exit 1
    cp .runtime/sdk-build-linux.json config/sdk-build.json
    if [ ! -d .git ]; then
        git init -q .
        git -c user.name=harness -c user.email=harness@local commit -q --allow-empty -m "binding evaluation tree"
    fi
    export TN_POLARS_OPA="$G/.runtime/dependencies/opa" POLARS_MAX_THREADS=16
    .venv/bin/python -m experiments.paper_evaluation.run --mode primitive --rows "$rows" --with-model \
        --run-directory "$R" --unity-url http://127.0.0.1:18080 \
        --binary .runtime/dependencies/tn-llama/llama-server \
        --model-path "$HOME/tn-cuda/models/Qwen3-4B-Q4_K_M.gguf" \
        --sdk-build-record .runtime/sdk-build-linux.json --port 18325 --gpu-layers 99 2>&1 | tail -60
}

"$@"
