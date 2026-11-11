"""Run the benchmark's per-trial model process on an SSH-connected GPU host."""

import io
import json
import shlex
import subprocess
import tarfile
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4


def input_bundle(config):
    config = Path(config).resolve()
    settings = json.loads(config.read_bytes())
    trial = config.parent.parent
    roots = [
        config.parent,
        Path(settings["governed_objects"]["native_reader_config_path"]).resolve().parent,
        Path(settings["output_tn_config_path"]).resolve().parent,
    ]
    if any(not path.is_relative_to(trial) for path in roots):
        raise ValueError("Model session files must be within the trial directory")
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz", compresslevel=1) as archive:
        for root in roots:
            archive.add(root, arcname=root.as_posix().lstrip("/"))
    return buffer.getvalue(), roots


class RemoteHost:
    def __init__(self, config):
        self.settings = json.loads(Path(config).read_bytes())
        self.worker = self.settings["worker"]
        self.options = [
            "ssh", "-i", self.settings["identity_file"],
            "-p", str(self.settings["port"]),
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=3", "-o", "ControlMaster=auto",
            "-o", "ControlPersist=600", "-S", self.settings["control_path"],
        ]
        self.target = self.settings["user"] + "@" + self.settings["host"]

    def command(self, arguments, **kwargs):
        return subprocess.run(
            [*self.options, self.target, shlex.join(arguments)],
            check=True, capture_output=True, timeout=180, **kwargs,
        )

    def version(self, binary):
        kind = "plain" if Path(binary).parent.name == "plain" else "tn"
        reply = self.command([self.settings[kind + "_binary"], "--version"])
        return (reply.stdout + reply.stderr).decode()

    def _forward(self, port, action, *, check=True):
        return subprocess.run(
            [*self.options, "-O", action, "-L", f"127.0.0.1:{port}:127.0.0.1:{port}",
             self.target],
            check=check, capture_output=True, timeout=20,
        )

    def _upload(self, config):
        payload, roots = input_bundle(config)
        self.command(["tar", "-xzf", "-", "-C", "/"], input=payload)
        return roots, len(payload)

    def _download(self, roots):
        paths = [path.as_posix().lstrip("/") for path in roots]
        reply = self.command(["tar", "-czf", "-", "-C", "/", "--", *paths])
        with tarfile.open(fileobj=io.BytesIO(reply.stdout), mode="r:gz") as archive:
            for member in archive.getmembers():
                target = Path("/") / member.name
                if not any(target.resolve().is_relative_to(root) for root in roots):
                    raise ValueError("Returned server file is outside its trial directory")
            archive.extractall("/", filter="data")

    @contextmanager
    def server(self, *, kind, directory, port, api_key, config=None, gpu_layers=None):
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        roots, staged_bytes = self._upload(config) if config is not None else ([], 0)
        remote_directory = str(directory) if config else "/tmp/tn-plain-" + uuid4().hex
        pid_path = remote_directory + "/.cloud-server.pid"
        arguments = [
            self.settings[kind + "_binary"], "--model", self.settings["model"],
            "--host", "127.0.0.1", "--port", str(port), "--ctx-size", "16384",
            "--parallel", "1", "--jinja", "--no-agent", "--no-ui",
            "--no-ui-mcp-proxy", "--no-context-shift", "--no-cache-prompt",
            "--cache-reuse", "0", "--no-cache-idle-slots", "--cache-ram", "0", "--n-gpu-layers",
            str(999 if gpu_layers is None else gpu_layers),
        ]
        environment = {"LLAMA_API_KEY": api_key}
        if config is not None:
            settings = json.loads(Path(config).read_bytes())
            environment.update(
                TN_LLAMA_CONFIG=str(config),
                TN_LLAMA_EXPECTED_MODEL_SHA256="sha256:" + settings["model_sha256"],
            )
        plan = {"arguments": arguments, "environment": environment, "pid_path": pid_path}
        self.command(["true"])
        self._forward(port, "forward")
        started = time.perf_counter()
        with ((directory / "server.stdout.log").open("wb") as stdout,
              (directory / "server.stderr.log").open("wb") as stderr):
            process = subprocess.Popen(
                [*self.options, self.target, shlex.join(["python3", self.worker])],
                stdin=subprocess.PIPE, stdout=stdout, stderr=stderr,
            )
            try:
                process.stdin.write(json.dumps(plan).encode())
                process.stdin.close()
                base_url = f"http://127.0.0.1:{port}"
                deadline = time.monotonic() + 180
                while True:
                    if process.poll() is not None:
                        raise RuntimeError("Remote model process exited; inspect server logs")
                    try:
                        with urllib.request.urlopen(base_url + "/health", timeout=2) as reply:
                            if reply.status == 200:
                                break
                    except (OSError, urllib.error.URLError):
                        pass
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Remote model server readiness timed out")
                    time.sleep(0.25)
                (directory / "remote-transport.json").write_text(json.dumps({
                    "host": self.settings["host"], "port": port,
                    "staged_bytes": staged_bytes, "ready_seconds": time.perf_counter() - started,
                }, indent=2) + "\n")
                yield base_url
            finally:
                try:
                    self.command(["python3", self.worker, "--stop", pid_path])
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.terminate()
                        process.wait(timeout=10)
                    if config is not None:
                        self._download([roots[0], roots[2]])
                finally:
                    if process.poll() is None:
                        process.terminate()
                    self._forward(port, "cancel", check=False)

    @contextmanager
    def governed(self, *, config, port, api_key, gpu_layers=None, **_kwargs):
        with self.server(kind="tn", directory=Path(config).parent, config=config,
                         port=port, api_key=api_key, gpu_layers=gpu_layers) as url:
            yield url

    @contextmanager
    def plain(self, directory, *, port, gpu_layers=999, **_kwargs):
        key = uuid4().hex
        with self.server(kind="plain", directory=directory, port=port,
                         api_key=key, gpu_layers=gpu_layers) as url:
            yield url, key
