#!/usr/bin/env bash
# Prepare an Ubuntu 24.04 host for the evaluation from a checkout of this repository.
#
# Usage: setup_linux_evaluation.sh SDK_WHEEL TN_SERVER_DIR PLAIN_SERVER_DIR MODEL_GGUF
#
# SDK_WHEEL is the manylinux tn-proto wheel of the pinned version. TN_SERVER_DIR
# and PLAIN_SERVER_DIR hold the servers from scripts/build_llama.sh and
# scripts/build_plain_llama.sh. The script writes .runtime/sdk-build-linux.json,
# which the evaluation commands take as --sdk-build-record.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
wheel="$1"; tn_server="$2"; plain_server="$3"; model="$4"
opa_version=1.18.2
cd "$root"
export DEBIAN_FRONTEND=noninteractive
apt_options=(-o Acquire::ForceIPv4=true -o Acquire::http::Timeout=20 -o Acquire::Retries=3)
sudo -E apt-get "${apt_options[@]}" update -qq
sudo -E apt-get "${apt_options[@]}" install -y -qq docker.io sqlite3 cmake ninja-build build-essential \
    pkg-config libssl-dev eatmydata
sudo usermod -aG docker "$USER"
command -v uv >/dev/null || curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
mkdir -p .runtime/dependencies/tn-llama .runtime/llama-build/plain-cpu/bin .artifacts/models
cp -a "$tn_server"/. .runtime/dependencies/tn-llama/
cp -a "$plain_server"/. .runtime/llama-build/plain-cpu/bin/
chmod +x .runtime/dependencies/tn-llama/llama-server .runtime/llama-build/plain-cpu/bin/llama-server
ln -sf "$(realpath "$model")" .artifacts/models/
uv python install 3.12
uv venv --python 3.12 .venv
python_bin="$PWD/.venv/bin/python"
requirements="$(mktemp)"
uv export --frozen --no-hashes --no-emit-project --extra dev \
    | grep -vE '^(tn-proto|tn-polars|tn-llama-client|\./|-e |#|    #)' | grep -v 'vendor/wheels' > "$requirements"
uv pip install -q --no-config --python "$python_bin" --no-deps -r "$requirements"
uv pip install -q --no-config --python "$python_bin" --no-deps "$wheel"
uv pip install -q --no-config --python "$python_bin" --no-deps \
    -e dependencies/tn-polars -e dependencies/tn-llama-client -e .
curl -fsSL -o .runtime/dependencies/opa \
    "https://github.com/open-policy-agent/opa/releases/download/v${opa_version}/opa_linux_amd64_static"
chmod +x .runtime/dependencies/opa
"$python_bin" - "$wheel" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

import importlib.metadata
import tn._native as native

digest = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
Path(".runtime/sdk-build-linux.json").write_text(json.dumps({
    "distribution": "tn-proto", "version": importlib.metadata.version("tn-proto"),
    "wheel_sha256": digest(sys.argv[1]),
    "install": {"native_module_sha256": digest(native.__file__)},
}, indent=2), encoding="utf-8")
PY
sudo sg docker -c "$python_bin scripts/install_unity.py --port 18080"
echo "Evaluation host ready. Use --sdk-build-record .runtime/sdk-build-linux.json."
