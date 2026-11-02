"""Native builds reject stale source snapshots and divergent runtime copies."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/runtime_sources.py"


def snapshot(root, content=b"runtime"):
    path = root / "crates/tn-runtime/src/session.rs"
    path.parent.mkdir(parents=True)
    path.write_bytes(content)
    (root / "source-manifest.json").write_text(json.dumps({"files": [{
        "path": "crates/tn-runtime/src/session.rs",
        "sha256": hashlib.sha256(content).hexdigest(),
    }]}))
    return path


def run(source, *args):
    return subprocess.run([sys.executable, str(SCRIPT), "--source", str(source), *map(str, args)],
                          text=True, capture_output=True)


def test_source_change_is_rejected_before_build(tmp_path):
    path = snapshot(tmp_path)
    path.write_bytes(b"different execution")
    result = run(tmp_path)
    assert result.returncode != 0
    assert "session.rs" in result.stderr


def test_matching_snapshot_and_runtime_are_accepted(tmp_path):
    source, upstream = tmp_path / "source", tmp_path / "upstream"
    snapshot(source)
    snapshot(upstream)
    (upstream / "crates/tn-runtime-py").mkdir()
    (upstream / "crates/tn-runtime-py/Cargo.toml").write_text("python bridge")
    result = run(source, "--against", upstream)
    assert result.returncode == 0, result.stderr


def test_runtime_drift_is_rejected_even_when_each_manifest_matches(tmp_path):
    source, upstream = tmp_path / "source", tmp_path / "upstream"
    snapshot(source)
    snapshot(upstream, b"other execution")
    result = run(source, "--against", upstream)
    assert result.returncode != 0
    assert "runtime copies differ" in result.stderr
    assert "session.rs" in result.stderr


def test_platform_line_endings_do_not_hide_or_invent_source_drift(tmp_path):
    source, upstream = tmp_path / "source", tmp_path / "upstream"
    snapshot(source, b"runtime\n")
    path = snapshot(upstream, b"runtime\r\n")
    assert run(source, "--against", upstream).returncode == 0
    path.write_bytes(b"other runtime\r\n")
    assert run(source, "--against", upstream).returncode != 0


def test_unrecorded_runtime_module_is_rejected(tmp_path):
    snapshot(tmp_path)
    (tmp_path / "crates/tn-runtime/src/admission.rs").write_text("admission")
    result = run(tmp_path)
    assert result.returncode != 0
    assert "admission.rs" in result.stderr


def test_refresh_does_not_hide_divergence(tmp_path):
    source, upstream = tmp_path / "source", tmp_path / "upstream"
    snapshot(source)
    snapshot(upstream, b"other execution")
    before = (source / "source-manifest.json").read_bytes()
    result = run(source, "--against", upstream, "--refresh")
    assert result.returncode != 0
    assert (source / "source-manifest.json").read_bytes() == before


def test_refresh_records_shared_module_then_verifies(tmp_path):
    snapshot(tmp_path)
    (tmp_path / "crates/tn-runtime/src/admission.rs").write_bytes(b"admission")
    result = run(tmp_path, "--refresh")
    assert result.returncode == 0, result.stderr
    assert run(tmp_path).returncode == 0
    entries = json.loads((tmp_path / "source-manifest.json").read_bytes())["files"]
    assert len(entries) == 2
    assert next(item for item in entries if item["path"].endswith("admission.rs"))["sha256"] == (
        hashlib.sha256(b"admission").hexdigest()
    )


@pytest.mark.parametrize("path", ["../outside.rs", "/outside.rs", "C:/outside.rs"])
def test_manifest_cannot_read_outside_snapshot(tmp_path, path):
    snapshot(tmp_path)
    (tmp_path / "source-manifest.json").write_text(json.dumps({"files": [{
        "path": path, "sha256": "0" * 64,
    }]}))
    result = run(tmp_path)
    assert result.returncode != 0
    assert "relative source path" in result.stderr
