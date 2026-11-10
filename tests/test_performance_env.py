"""Execution paths match the native SDK and model binary platform."""

import importlib
from pathlib import Path

import pytest


@pytest.mark.parametrize("platform_name,binary,expected", [
    ("nt", "llama-server", True),
    ("nt", "llama-server.exe", False),
    ("nt", "llama-server.EXE", False),
    ("posix", "llama-server", False),
])
def test_model_execution_selects_wsl_only_for_linux_binaries_on_windows(
    platform_name, binary, expected
):
    module = importlib.import_module("experiments.paper_evaluation.performance_env")
    assert module.model_uses_wsl(Path(binary), platform_name=platform_name) is expected


@pytest.mark.parametrize("platform_name,binary,library", [
    ("nt", "llama-server", "libllama-server-impl.so"),
    ("nt", "llama-server.exe", "llama-server-impl.dll"),
    ("posix", "llama-server", "libllama-server-impl.so"),
])
def test_implementation_hash_target_is_the_platform_adjacent_library(
    tmp_path, platform_name, binary, library
):
    module = importlib.import_module("experiments.paper_evaluation.performance_env")
    expected = tmp_path / library
    with pytest.raises(FileNotFoundError):
        module.implementation_library(tmp_path / binary, platform_name=platform_name)
    expected.write_bytes(b"implementation")
    assert module.implementation_library(
        tmp_path / binary, platform_name=platform_name
    ) == expected.resolve()


def test_sdk_hash_target_is_the_installed_native_module():
    module = importlib.import_module("experiments.paper_evaluation.performance_env")
    native = importlib.import_module("tn._native")
    assert module.native_module_path() == Path(native.__file__).resolve()
    assert module.native_module_path().is_file()
