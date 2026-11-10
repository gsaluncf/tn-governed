#!/usr/bin/env bash
# Build Linux runtime payloads with CUDA 12.8 before allocating cloud GPUs.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
work="${TN_CLOUD_BUILD_ROOT:-$HOME/tn-cloud-package}"
mkdir -p "$work"
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:/usr/local/cuda-12.8/bin:$PATH"
export CUDACXX=/usr/local/cuda-12.8/bin/nvcc
export CUDA_HOME=/usr/local/cuda-12.8
python3 - "$root" "$work" "${1:-}" <<'PY'
import importlib.util,shutil,sys,tarfile
from pathlib import Path
root,work=map(Path,sys.argv[1:3])
spec=importlib.util.spec_from_file_location('cloud_package',root/'deployment/package.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
stage=work/'project'
if stage.exists():
    if sys.argv[3] == '--resume':
        print('Resuming package build:',stage)
        raise SystemExit(0)
    raise SystemExit('Use an empty TN_CLOUD_BUILD_ROOT to preserve earlier package builds')
for source,name in module.source_files():
    target=stage/name;target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copy2(source,target)
shutil.copytree(root/'native/tn-llama',stage/'native/tn-llama',ignore=shutil.ignore_patterns('.git','target','__pycache__'))
shutil.copytree(root/'vendor/wheels',stage/'vendor/wheels')
build=stage/'.runtime/llama-build';build.mkdir(parents=True)
(build/'upstream').symlink_to(root/'.runtime/llama-build/upstream',target_is_directory=True)
with tarfile.open(root/'.runtime/source-packages/tn_proto-2026.9.13b1+policy.1.tar.gz') as archive:
    archive.extractall(work/'sdk',filter='data')
print('Project snapshot:',stage)
PY
mkdir -p "$work/wheelhouse"
if [[ ! -d "$work/git-metadata/.git" ]]; then
    git clone --quiet --no-checkout --depth 1 --no-local "$root" "$work/git-metadata"
fi
cd "$work/sdk/tn_proto-2026.9.13b1+policy.1"
if ! rg -q 'mod manifest_cache;' crypto/tn-core/src/governed/reader/mod.rs; then
    patch --batch --forward -p1 < "$root/deployment/native_metadata.patch"
fi
if ! rg -q 'fn shared_groups' crypto/tn-core/src/governed/writer.rs; then
    patch --batch --forward -p1 < "$root/deployment/native_copy_on_write.patch"
fi
if ! rg -q 'fn canonical_object_fields' crypto/tn-core/src/canonical.rs; then
    patch --batch --forward -p1 < "$root/deployment/native_single_pass.patch"
fi
if ! rg -q 'fn group_fields' crypto/tn-core/src/governed/data/edit.rs; then
    # These files in the pinned archive use CRLF; patch context uses LF.
    sed -i 's/\r$//' crypto/tn-core-py/src/governed/data.rs crypto/tn-core-py/src/governed/codec.rs
    patch --batch --forward -p1 < "$root/deployment/native_python_reads.patch"
fi
if ! rg -q 'fn decrypt_shared' crypto/tn-core/src/governed/reader/mod.rs; then
    patch --batch --forward -p1 < "$root/deployment/native_receipt_sharing.patch"
fi
if ! rg -q 'fn new_with_owned_groups' crypto/tn-core/src/governed/data/mod.rs; then
    patch --batch --forward -p1 < "$root/deployment/native_owned_groups.patch"
fi
cargo metadata --offline --format-version 1 > "$work/sdk-metadata.json"
CARGO_TARGET_DIR="$work/sdk-target" maturin build --release --locked --compatibility linux --out "$work/wheelhouse"
cd "$work/project"
uv export --frozen --no-hashes --no-emit-project --extra dev > "$work/requirements-export.txt"
python3 - "$work" <<'PY'
import sys
from pathlib import Path
work=Path(sys.argv[1])
lines=work.joinpath('requirements-export.txt').read_text().splitlines()
lines=[line for line in lines if not line.startswith(('tn-proto','tn-polars','tn-llama-client','./','-e ','#')) and 'vendor/wheels' not in line]
work.joinpath('requirements-linux.txt').write_text('\n'.join(lines)+'\nhatchling>=1.27,<2\npip\n')
PY
python3 -m pip download --only-binary=:all: --dest "$work/wheelhouse" -r "$work/requirements-linux.txt"
python3 -m pip wheel --no-deps --wheel-dir "$work/wheelhouse" . dependencies/tn-polars dependencies/tn-llama-client
curl --fail --location --retry 2 -o "$work/opa" https://github.com/open-policy-agent/opa/releases/download/v1.18.2/opa_linux_amd64_static
cp -a "$root/deployment/". deployment/
python3 deployment/package.py --target azure --wheelhouse "$work/wheelhouse" \
    --opa "$work/opa" --git-dir "$work/git-metadata/.git" --output "$root/dist/cloud"
export TN_BUILD_JOBS="${TN_BUILD_JOBS:-14}"
export TN_CUDA_ARCHITECTURES="86-real;89-real;120-real"
bash scripts/build_llama.sh cuda
bash deployment/build_plain.sh
python3 deployment/package.py --target runpod --wheelhouse "$work/wheelhouse" \
    --tn-server .runtime/dependencies/tn-llama --plain-server .runtime/llama-build/plain-cuda/bin \
    --opa "$work/opa" --git-dir "$work/git-metadata/.git" --output "$root/dist/cloud"
printf '%s\n' 'Runpod runtime archive prepared.'
