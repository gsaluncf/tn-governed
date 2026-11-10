"""Create bulk-transfer Linux deployment archives from selected runtime files."""

import argparse
import hashlib
import json
import os
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIRS = (
    "src", "dependencies", "experiments/paper_evaluation",
    "config", "examples", "scripts", "deployment",
)
SKIP = {
    ".git", ".venv", "__pycache__", "node_modules", "target", "results",
    ".pytest_cache", ".ruff_cache",
}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_files():
    for directory in SOURCE_DIRS:
        for base, dirs, files in os.walk(ROOT / directory):
            dirs[:] = sorted(name for name in dirs if name not in SKIP)
            for name in sorted(files):
                path = Path(base) / name
                if name.startswith(".env") or path.suffix in {".pyc", ".gguf", ".pem", ".key"}:
                    continue
                if path.is_symlink():
                    raise ValueError(f"Source link requires an explicit package entry: {path}")
                yield path, path.relative_to(ROOT).as_posix()
    for name in ("pyproject.toml", "uv.lock"):
        yield ROOT / name, name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--tn-server", type=Path)
    parser.add_argument("--plain-server", type=Path)
    parser.add_argument("--opa", type=Path, required=True)
    parser.add_argument("--git-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", choices=("azure", "runpod"), required=True)
    args = parser.parse_args()
    if args.target == "runpod" and (args.tn_server is None or args.plain_server is None):
        parser.error("Runpod requires both --tn-server and --plain-server")
    entries = list(source_files())
    for path in sorted(args.git_dir.rglob("*")):
        if path.is_file():
            entries.append((path, ".git/" + path.relative_to(args.git_dir).as_posix()))
    wheels = sorted(args.wheelhouse.glob("*.whl"))
    if not any(p.name.startswith("tn_proto-2026.9.13b1+policy.1-") for p in wheels):
        raise ValueError("The pinned Linux TN wheel is required")
    for wheel in wheels:
        if "win_" in wheel.name or "macosx" in wheel.name:
            raise ValueError(f"Non-Linux wheel: {wheel.name}")
        entries.append((wheel, "wheelhouse/" + wheel.name))
    for directory, target in ((args.tn_server, "runtime/tn"), (args.plain_server, "runtime/plain")):
        if directory is None:
            continue
        if not (directory / "llama-server").is_file():
            raise FileNotFoundError(directory / "llama-server")
        for path in sorted(directory.iterdir()):
            if path.name == "llama-server" or ".so" in path.name or path.name == "build.json":
                entries.append((path.resolve(), target + "/" + path.name))
    entries.append((args.opa, "runtime/opa"))
    args.output.mkdir(parents=True, exist_ok=True)
    output = args.output / ("tn-" + args.target + "-runtime.tar.gz")
    manifest = {"target": args.target, "files": []}
    shared_runtime_files = {}
    with tarfile.open(output, "w:gz", compresslevel=3) as archive:
        for path, name in entries:
            record = {"path": name, "bytes": path.stat().st_size, "sha256": digest(path)}
            manifest["files"].append(record)
            info = archive.gettarinfo(str(path), arcname="tn-runtime/" + name)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o755 if name.endswith(".sh") or name.startswith("runtime/") else 0o644
            key = (record["sha256"], record["bytes"])
            if name.startswith("runtime/") and key in shared_runtime_files:
                info.type = tarfile.LNKTYPE
                info.linkname = shared_runtime_files[key]
                info.size = 0
                archive.addfile(info)
            else:
                if name.startswith("runtime/"):
                    shared_runtime_files[key] = info.name
                with path.open("rb") as stream:
                    archive.addfile(info, stream)
        import io

        payload = (json.dumps(manifest, indent=2) + "\n").encode()
        info = tarfile.TarInfo("tn-runtime/deployment-manifest.json")
        info.size = len(payload)
        info.mode = 0o644
        archive.addfile(info, io.BytesIO(payload))
    checksum = digest(output)
    output.with_suffix(output.suffix + ".sha256").write_text(f"{checksum}  {output.name}\n")
    print(json.dumps({
        "archive": str(output), "files": len(entries),
        "bytes": output.stat().st_size, "sha256": checksum,
    }))


if __name__ == "__main__":
    main()
