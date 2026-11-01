"""Select model execution and fingerprint the installed native implementation."""

from __future__ import annotations

import importlib
import os
from pathlib import Path


def model_uses_wsl(binary, *, platform_name=None):
    platform_name = os.name if platform_name is None else platform_name
    return platform_name == "nt" and Path(binary).suffix.lower() != ".exe"


def implementation_library(binary, *, platform_name=None):
    platform_name = os.name if platform_name is None else platform_name
    native_windows = platform_name == "nt" and not model_uses_wsl(
        binary, platform_name=platform_name
    )
    filename = "llama-server-impl.dll" if native_windows else "libllama-server-impl.so"
    path = Path(binary).resolve().parent / filename
    if not path.is_file():
        raise FileNotFoundError(path)
    return path


def native_module_path():
    module = importlib.import_module("tn._native")
    path = Path(module.__file__).resolve()
    if not path.is_file():
        raise FileNotFoundError(path)
    return path
