#!/usr/bin/env bash
# Install the bundled wheels into a Python 3.12 environment on Ubuntu 24.04.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
python="${TN_PYTHON:-/usr/bin/python3}"
"$python" -c 'import sys; assert sys.version_info[:2] == (3, 12), "Python 3.12 is required"'
"$python" - <<'PY'
import hashlib,json
from pathlib import Path
for entry in json.loads(Path('deployment-manifest.json').read_text())['files']:
    with Path(entry['path']).open('rb') as stream:
        actual=hashlib.file_digest(stream,'sha256').hexdigest()
    if actual != entry['sha256']:
        raise SystemExit('Package checksum mismatch: '+entry['path'])
print('Package file checksums verified')
PY
uv --no-config venv --python "$python" .venv
uv --no-config pip install --python .venv/bin/python --offline --no-deps wheelhouse/*.whl
mkdir -p .runtime
.venv/bin/python - <<'PY'
import hashlib,importlib.metadata,json
from pathlib import Path
import tn._native
wheel=next(Path('wheelhouse').glob('tn_proto-2026.9.13b1+policy.1-*.whl'))
def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()
Path('.runtime/sdk-build-linux.json').write_text(json.dumps({
    'distribution':'tn-proto','version':importlib.metadata.version('tn-proto'),
    'wheel_sha256':digest(wheel),'install':{'native_module_sha256':digest(tn._native.__file__)},
},indent=2)+'\n')
print('Installed Linux TN runtime:',importlib.metadata.version('tn-proto'))
PY
chmod +x runtime/opa
for server in runtime/tn/llama-server runtime/plain/llama-server; do
    if [[ -f "$server" ]]; then chmod +x "$server"; fi
done
printf '%s\n' 'Runtime installed. The GGUF model and Unity URL are supplied separately.'
