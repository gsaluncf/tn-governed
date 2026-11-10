"""Verify native source digests and optionally compare a standalone runtime checkout."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "native/tn-llama"
SHARED_TREES = (
    "crates/tn-runtime/src", "crates/tn-test-tools/src", "include", "patches/llama.cpp",
)
SHARED_FILES = (
    "crates/tn-runtime/Cargo.toml", "crates/tn-runtime/build.rs",
    "crates/tn-test-tools/Cargo.toml", "crates/tn-test-tools/build.rs",
)


def shared_files(root):
    paths = {path.relative_to(root).as_posix()
             for tree in SHARED_TREES for path in (root / tree).rglob("*") if path.is_file()}
    return paths | {name for name in SHARED_FILES if (root / name).is_file()}


def source_path(root, name):
    if (not isinstance(name, str) or not name or "\\" in name
            or PurePosixPath(name).is_absolute() or PureWindowsPath(name).drive
            or ".." in PurePosixPath(name).parts):
        raise ValueError(f"expected a relative source path: {name!r}")
    path = root / name
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"expected a relative source path within the snapshot: {name!r}")
    return path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_text(path):
    # Git may materialize the same text with CRLF on Windows and LF in WSL.
    return path.read_bytes().replace(b"\r\n", b"\n")


def verify(source, against=None, *, refresh=False):
    source = Path(source)
    shared = shared_files(source)
    if not shared:
        raise ValueError(f"no shared runtime sources in {source}")
    if against is not None:
        against = Path(against)
        other = shared_files(against)
        different = sorted(shared ^ other | {
            name for name in shared & other
            if source_text(source_path(source, name)) != source_text(source_path(against, name))
        })
        if different:
            raise ValueError("runtime copies differ: " + ", ".join(different))
    manifest_path = source / "source-manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    entries = manifest["files"]
    recorded = {entry["path"]: entry for entry in entries}
    if len(recorded) != len(entries):
        raise ValueError("duplicate source manifest path")
    for name in recorded:
        source_path(source, name)
    if refresh:
        for name in sorted(recorded.keys() | shared):
            recorded[name] = {"path": name, "sha256": digest(source_path(source, name))}
        manifest["files"] = [recorded[name] for name in sorted(recorded)]
        manifest_path.write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n",
        )
    unrecorded = sorted(shared - recorded.keys())
    if unrecorded:
        raise ValueError("unrecorded runtime source: " + ", ".join(unrecorded))
    mismatches = sorted(name for name, entry in recorded.items()
                        if digest(source_path(source, name)) != entry["sha256"])
    if mismatches:
        raise ValueError("source manifest mismatch: " + ", ".join(mismatches))
    return len(recorded), len(shared)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--against", type=Path, help="Standalone tn-llama checkout to compare")
    parser.add_argument("--refresh", action="store_true", help="Record reviewed source digests")
    args = parser.parse_args()
    try:
        total, shared = verify(args.source, args.against, refresh=args.refresh)
    except (ValueError, KeyError, TypeError, OSError) as error:
        parser.exit(1, f"Native source verification failed: {error}\n")
    comparison = f" and {shared} shared runtime files" if args.against else ""
    print(f"Verified {total} source digests{comparison}")


if __name__ == "__main__":
    main()
