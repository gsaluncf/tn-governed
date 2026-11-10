"""Record a fresh source manifest for an assembled native tree: every source file and its digest.

usage: python3 native_manifest.py <native/tn-llama> <tn-proto description> <tn-llama description>
"""
import hashlib
import json
import sys
from pathlib import Path

SKIP = {"target", "__pycache__", ".git"}


def main(root, tn_proto, tn_llama):
    root = Path(root)
    manifest_path = root / "source-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    files = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if not path.is_file() or SKIP & set(relative.parts) or relative.name == "source-manifest.json":
            continue
        files.append({"path": relative.as_posix(), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    manifest["tn_proto"] = {"commit": tn_proto}
    manifest["tn_llama"] = {"commit": tn_llama,
                            "source_identity": "The file digests below identify this complete source snapshot."}
    manifest["files"] = files
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"recorded {len(files)} files")


if __name__ == "__main__":
    main(*sys.argv[1:4])
