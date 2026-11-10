"""Measurement manifests identify shared libraries and native build inputs."""

import hashlib
import json
from types import SimpleNamespace


def test_environment_manifest_tracks_library_bytes_and_cmake_configuration(tmp_path):
    from experiments.paper_evaluation.performance import environment_manifest

    binaries = {}
    for name in ("binary", "plain_binary"):
        build = tmp_path / name
        bundle = build / "bin"
        bundle.mkdir(parents=True)
        binaries[name] = bundle / "llama-server"
        binaries[name].write_bytes(b"engine-launcher")
        (bundle / "libllama-server-impl.so").write_bytes(name.encode())
        (bundle / "ggml.dll").write_bytes(b"cpu-library")
        (bundle / "build.json").write_text(json.dumps({"backend": "cpu"}))
        (build / "CMakeCache.txt").write_text(
            "//Build configuration\nCMAKE_BUILD_TYPE:STRING=Release\n"
            "GGML_CUDA:BOOL=OFF\nLLAMA_TN_GOVERNED:BOOL="
            + ("ON" if name == "binary" else "OFF")
            + "\n"
        )
    args = SimpleNamespace(
        **binaries, model_path=None, opa=None, unity_url="http://localhost:18080"
    )
    before = environment_manifest(args, {"model": False})
    for name in binaries:
        entry = before[name]
        assert entry["adjacent_shared_libraries"]["libllama-server-impl.so"]["sha256"] == (
            hashlib.sha256(name.encode()).hexdigest()
        )
        assert entry["adjacent_shared_libraries"]["ggml.dll"]["bytes"] == len(b"cpu-library")
        assert entry["build_manifest"]["content"]["backend"] == "cpu"
        assert entry["cmake_configuration"]["options"]["CMAKE_BUILD_TYPE"] == "Release"
        assert entry["cmake_configuration"]["options"]["GGML_CUDA"] == "OFF"
    (binaries["plain_binary"].parent / "libllama-server-impl.so").write_bytes(b"different-engine")
    after = environment_manifest(args, {"model": False})
    assert before["plain_binary"]["sha256"] == after["plain_binary"]["sha256"]
    assert (
        before["plain_binary"]["adjacent_shared_libraries"]
        != after["plain_binary"]["adjacent_shared_libraries"]
    )
    assert any(path.endswith(".rs") for path in before["native_source_sha256"])
    assert "sqlite" in before["runtime_versions"]
    assert before["native_sdk"]["sha256"]
