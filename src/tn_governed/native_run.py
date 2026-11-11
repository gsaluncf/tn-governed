"""Own a local governed server process for a complete reference execution."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from contextlib import contextmanager
from pathlib import Path

from .native_reference import (
    finish_governed_reference,
    load_governed_reference,
    prepare_governed_reference,
    write_governed_runtime_config,
)


def wsl_path(path: Path) -> str:
    path = Path(path).resolve()
    if not path.drive or len(path.drive) != 2:
        raise ValueError("the WSL reference runner requires a drive-backed Windows path")
    return "/mnt/" + path.drive[0].lower() + path.as_posix()[2:]


def wsl_command():
    """Use the selected WSL distribution, or the user's default."""
    distribution = os.environ.get("TN_WSL_DISTRO")
    return ["wsl", *(["-d", distribution] if distribution else []), "--"]


def _signal_owned_wsl(pid, signal):
    try:
        result = subprocess.run(
            [*wsl_command(), "kill", signal, "--", pid],
            check=False, timeout=10, capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _stop_owned_server(process, *, wsl, pid_path):
    """Signal the launcher's recorded Linux PID before stopping its WSL wrapper."""
    try:
        pid = pid_path.read_text(encoding="ascii").strip() if wsl else ""
    except (OSError, UnicodeError):
        pid = ""
    owned_linux_pid = pid.isascii() and pid.isdecimal() and 1 < int(pid) < 2**31
    if wsl and owned_linux_pid:
        term_sent = _signal_owned_wsl(pid, "-TERM")
        if term_sent:
            try:
                process.wait(timeout=10)
                return
            except subprocess.TimeoutExpired:
                pass
        _signal_owned_wsl(pid, "-KILL")
        try:
            process.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            pass
    elif process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
            return
        except subprocess.TimeoutExpired:
            pass
    if process.poll() is None:
        process.kill()
        process.wait(timeout=5)


# llama.cpp offloads at most a model's own layers, so this places every layer on the GPU.
ALL_GPU_LAYERS = 999


@contextmanager
def governed_server(
    *, binary: Path, model: Path, config: Path, port: int, api_key: str, wsl: bool = False,
    gpu_layers: int | None = None,
):
    """Start one native process, wait for readiness, and stop that owned process."""
    if gpu_layers is not None and (type(gpu_layers) is not int or gpu_layers < 0):
        raise ValueError("GPU layers must be a nonnegative integer or None")
    if not 1 <= port <= 65535 or not api_key.strip():
        raise ValueError("a valid local port and API key are required")
    with socket.socket() as probe:
        probe.settimeout(0.5)
        if probe.connect_ex(("127.0.0.1", port)) == 0:
            raise ValueError("the model port is already occupied; choose an unused local port")
    with socket.socket() as probe:
        # A preceding server on this port can leave connections in TIME_WAIT.
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(("127.0.0.1", port))
    directory = config.parent
    pid_path = directory / f"server-{uuid.uuid4().hex}.pid"
    translate = wsl_path if wsl else str
    settings = json.loads(config.read_bytes())
    args = [
        str(binary),
        "--model",
        str(model),
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--ctx-size",
        "16384",
        "--parallel",
        "1",
        "--jinja",
        "--no-agent",
        "--no-ui",
        "--no-ui-mcp-proxy",
        "--no-context-shift",
        "--no-cache-prompt",
        "--cache-reuse",
        "0",
        "--no-cache-idle-slots",
        "--cache-ram",
        "0",
        "--n-gpu-layers",
        str(ALL_GPU_LAYERS if gpu_layers is None else gpu_layers),
    ]
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("LLAMA_")
        and key not in {"TN_LLAMA_CONFIG", "TN_LLAMA_EXPECTED_MODEL_SHA256"}
    }
    config_root = (directory / "server-config-root").resolve()
    config_root.mkdir(exist_ok=True)
    native_env = {
        "TN_LLAMA_CONFIG": translate(config),
        "TN_LLAMA_EXPECTED_MODEL_SHA256": "sha256:" + settings["model_sha256"],
        "LLAMA_API_KEY": api_key,
    }
    if wsl:
        args[0], args[2] = translate(binary), translate(model)
        native_env["XDG_CONFIG_HOME"] = translate(config_root)
        # A fixed script avoids command-string quoting across Windows and WSL.
        launcher = directory / "server-exec.sh"
        launcher.write_text('echo $$ > "$1"\nshift\nexec "$@"\n', encoding="utf-8", newline="\n")
        args = [
            *wsl_command(),
            "sh",
            translate(launcher),
            translate(pid_path),
            "env",
            *[f"{key}={value}" for key, value in native_env.items()],
            *args,
        ]
    else:
        environment.update(native_env)
        environment.update(
            APPDATA=str(config_root), PROGRAMDATA=str(config_root),
            XDG_CONFIG_HOME=str(config_root),
        )
    with (
        (directory / "server.stdout.log").open("wb") as stdout,
        (directory / "server.stderr.log").open("wb") as stderr,
    ):
        process = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            env=environment,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        try:
            base_url = f"http://127.0.0.1:{port}"
            deadline = time.monotonic() + 180
            while True:
                if process.poll() is not None:
                    raise RuntimeError("governed server exited during startup; inspect server logs")
                try:
                    with urllib.request.urlopen(base_url + "/health", timeout=2) as response:
                        if response.status == 200:
                            break
                except (OSError, urllib.error.URLError):
                    pass
                if time.monotonic() >= deadline:
                    raise TimeoutError("governed server readiness timed out")
                time.sleep(0.25)
            yield base_url
        finally:
            _stop_owned_server(process, wsl=wsl, pid_path=pid_path)


def run_native_reference(
    *,
    directory: Path,
    unity_url: str,
    binary: Path,
    model: Path,
    port: int,
    api_key: str,
    wsl=False,
    resume=False,
    check_refusals=False,
):
    """Run the active native workflow or resume its already published calculation."""
    binary, model = Path(binary).resolve(), Path(model).resolve()
    if not binary.is_file() or not model.is_file():
        raise FileNotFoundError("configure the built governed server and its local GGUF model")
    prepared = (
        load_governed_reference(directory)
        if resume
        else prepare_governed_reference(directory, unity_url=unity_url)
    )
    with prepared:
        runtime = write_governed_runtime_config(
            prepared, model=model, binary=binary, path_for_runtime=wsl_path if wsl else str
        )
        with governed_server(
            binary=binary, model=model, config=runtime, port=port, api_key=api_key, wsl=wsl
        ) as base_url:
            if check_refusals:
                from .native_evaluation import verify_admission_refusals

                verify_admission_refusals(prepared, base_url=base_url, api_key=api_key)
            return finish_governed_reference(prepared, base_url=base_url, api_key=api_key)
