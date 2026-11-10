"""Ordinary-value report generation with the pinned llama.cpp inference engine."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.request
from contextlib import contextmanager, suppress
from pathlib import Path
from uuid import uuid4

from tn_governed.native_run import ALL_GPU_LAYERS, wsl_command, wsl_path
from tn_governed.values.report_profile import PlainReportText

from .case_study import NOTICE
from .processing_comparison import ordinary_case
from .run import PROMPT


def plain_request(brief):
    return {
        "messages": [
            {
                "role": "system",
                "content": "Write the requested internal HTML draft. "
                "Return only HTML, with no Markdown fence or commentary.",
            },
            {
                "role": "user",
                "content": PROMPT
                + "\nSupplied calculation: "
                + brief
                + "\nRequired review notice: "
                + NOTICE
                + "\nInclude the supplied calculation exactly as written in a visible paragraph.",
            },
        ],
        "temperature": 0,
        "max_tokens": 2048,
        "reasoning_effort": "none",
        "stream": False,
        "cache_prompt": False,
        "n_cache_reuse": 0,
        "n": 1,
    }


def response_html(response):
    choices = response.get("choices")
    if not isinstance(choices, list) or len(choices) != 1:
        raise ValueError("model response must contain one choice")
    choice = choices[0]
    message = choice.get("message", {})
    content = message.get("content")
    if (
        choice.get("finish_reason") != "stop"
        or message.get("tool_calls")
        or message.get("refusal")
        or not isinstance(content, str)
        or not content.strip()
    ):
        raise ValueError("ordinary model did not complete a text report")
    return content


@contextmanager
def ordinary_server(directory, *, binary, model, port, startup_timeout=180, gpu_layers=ALL_GPU_LAYERS):
    """Own a loopback-only inference process with prompt caching disabled."""
    if type(gpu_layers) is not int or gpu_layers < 1:
        raise ValueError("the plain baseline runs every model layer on the GPU")
    binary, model, directory = Path(binary).resolve(), Path(model).resolve(), Path(directory)
    linux = os.name == "nt" and binary.suffix.lower() != ".exe"
    translate = wsl_path if linux else str
    with socket.socket() as probe:
        # A preceding server on this port can leave connections in TIME_WAIT.
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(("127.0.0.1", port))
    key = uuid4().hex
    arguments = [
        translate(binary),
        "--model",
        translate(model),
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
        "--n-gpu-layers",
        str(gpu_layers),
    ]
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("LLAMA_")
        and key not in {"TN_LLAMA_CONFIG", "TN_LLAMA_EXPECTED_MODEL_SHA256"}
    }
    environment["LLAMA_API_KEY"] = key
    config_root = (directory / "server-config-root").resolve()
    config_root.mkdir(exist_ok=True)
    environment.update(
        APPDATA=str(config_root), PROGRAMDATA=str(config_root),
        XDG_CONFIG_HOME=str(config_root),
    )
    pid_file = directory / "server.pid"
    if linux:
        launcher = directory / "server-exec.sh"
        launcher.write_text('echo $$ > "$1"\nshift\nexec "$@"\n', encoding="utf-8", newline="\n")
        arguments = [
            *wsl_command(),
            "sh",
            translate(launcher),
            translate(pid_file),
            "env",
            "-u",
            "TN_LLAMA_CONFIG",
            "-u",
            "TN_LLAMA_EXPECTED_MODEL_SHA256",
            "LLAMA_API_KEY=" + key,
            "XDG_CONFIG_HOME=" + translate(config_root),
            *arguments,
        ]
    (directory / "server-parameters.json").write_text(
        json.dumps(
            {
                "binary": str(binary),
                "model": str(model),
                "context": 16384,
                "parallel": 1,
                "gpu_layers": gpu_layers,
                "prompt_cache": False,
                "wsl": linux,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    with (
        (directory / "server.stdout.log").open("wb") as stdout,
        (directory / "server.stderr.log").open("wb") as stderr,
    ):
        process = subprocess.Popen(
            arguments,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        try:
            base_url = f"http://127.0.0.1:{port}"
            deadline = time.monotonic() + startup_timeout
            while True:
                if process.poll() is not None:
                    raise RuntimeError("ordinary model server exited; inspect server logs")
                try:
                    with urllib.request.urlopen(base_url + "/health", timeout=2) as response:
                        if response.status == 200:
                            break
                except (OSError, urllib.error.URLError):
                    pass
                if time.monotonic() >= deadline:
                    raise TimeoutError("ordinary model server readiness timed out")
                time.sleep(0.25)
            yield base_url, key
        finally:
            if process.poll() is None:
                if linux and pid_file.is_file():
                    pid = pid_file.read_text().strip()
                    if pid.isdigit() and int(pid) > 1:
                        with suppress(OSError, subprocess.TimeoutExpired):
                            subprocess.run(
                                [*wsl_command(), "kill", "-TERM", "--", pid],
                                capture_output=True,
                                check=False,
                                timeout=10,
                                creationflags=subprocess.CREATE_NO_WINDOW,
                            )
                else:
                    process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    if linux and pid_file.is_file():
                        pid = pid_file.read_text().strip()
                        if pid.isdigit() and int(pid) > 1:
                            with suppress(OSError, subprocess.TimeoutExpired):
                                subprocess.run(
                                    [*wsl_command(), "kill", "-KILL", "--", pid],
                                    capture_output=True,
                                    check=False,
                                    timeout=10,
                                    creationflags=subprocess.CREATE_NO_WINDOW,
                                )
                    process.kill()
                    process.wait(timeout=5)


def _request_report(url, key, request_body, directory):
    """Send the plain model request and return the parsed response and its report HTML."""
    request = urllib.request.Request(
        url + "/v1/chat/completions",
        data=json.dumps(request_body).encode(),
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + key},
    )
    try:
        with urllib.request.urlopen(request, timeout=600) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        directory.joinpath("model-response-error.bin").write_bytes(exc.read())
        raise
    directory.joinpath("model-response.json").write_bytes(raw)
    body = json.loads(raw)
    return body, response_html(body)


def _inspected_text(report, directory):
    """Write the report and return its visible text."""
    directory.joinpath("report.html").write_text(report, encoding="utf-8")
    inspection = PlainReportText()
    inspection.feed(report)
    inspection.close()
    return " ".join("".join(inspection.parts).split())


def _generate_plain(directory, result, *, binary, model, port, gpu_layers=ALL_GPU_LAYERS):
    timings = result["timings_seconds"]
    request_body = plain_request(result["expected_content"])
    directory.joinpath("model-request.json").write_text(
        json.dumps(request_body, indent=2), encoding="utf-8"
    )
    startup = time.perf_counter()
    with ordinary_server(directory, binary=binary, model=model, port=port,
                         gpu_layers=gpu_layers) as (url, key):
        timings["server_start"] = time.perf_counter() - startup
        generation = time.perf_counter()
        try:
            body, report = _request_report(url, key, request_body, directory)
            visible = _inspected_text(report, directory)
        finally:
            # The TN interval runs from dispatch to a validated report in hand; so does this.
            timings["generation"] = time.perf_counter() - generation
    if result["expected_content"] not in visible or NOTICE not in visible:
        raise ValueError("ordinary report omits the exact calculation or required notice")
    result.update(
        completed=True,
        verified=True,
        model_usage=body.get("usage"),
        model_timings=body.get("timings"),
    )


def ordinary_model_case(directory, rows, *, binary, model, port, gpu_layers=ALL_GPU_LAYERS):
    directory = Path(directory)
    started = time.perf_counter()
    result = ordinary_case(directory, rows)
    result["completed"] = result["verified"] = False
    try:
        _generate_plain(directory, result, binary=binary, model=model, port=port,
                        gpu_layers=gpu_layers)
    except Exception as exc:
        result["error_type"] = type(exc).__name__
    finally:
        result["timings_seconds"]["total"] = time.perf_counter() - started
        directory.joinpath("case-summary.json").write_text(
            json.dumps(result, indent=2), encoding="utf-8"
        )
    return result
