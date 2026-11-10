import json
import socket
import subprocess
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from tn_governed.native_run import governed_server, wsl_command


def test_wsl_distribution_is_configurable(monkeypatch):
    monkeypatch.delenv("TN_WSL_DISTRO", raising=False)
    assert wsl_command() == ["wsl", "--"]
    monkeypatch.setenv("TN_WSL_DISTRO", "Research Linux")
    assert wsl_command() == ["wsl", "-d", "Research Linux", "--"]


def test_runner_refuses_an_occupied_port_before_launch(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "tn_governed.native_run.subprocess.Popen",
        lambda *_a, **_k: pytest.fail("process launched on an occupied port"),
    )
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        with (
            pytest.raises(ValueError, match="already occupied"),
            governed_server(
                binary=tmp_path / "server",
                model=tmp_path / "model",
                config=tmp_path / "config.json",
                port=listener.getsockname()[1],
                api_key="test",
            ),
        ):
            pytest.fail("another service's health response was accepted")


@pytest.mark.parametrize("gpu_layers", [-1, True, 1.5, "0"])
def test_gpu_layer_count_is_validated_before_launch(tmp_path, gpu_layers):
    with (
        pytest.raises(ValueError, match="GPU"),
        governed_server(binary=tmp_path / "server", model=tmp_path / "model",
                        config=tmp_path / "config", port=19381, api_key="test",
                        gpu_layers=gpu_layers),
    ):
        pytest.fail("invalid GPU layer count was accepted")


# Without an explicit count the launcher puts every model layer on the GPU, in or out of WSL.
@pytest.mark.parametrize("wsl,gpu_layers,expected", [(False, None, "999"),
                                                   (True, None, "999"), (True, 0, "0")])
def test_gpu_configuration_reaches_owned_process(tmp_path, monkeypatch, wsl, gpu_layers, expected):
    from tn_governed import native_run

    command = []

    class Process:
        returncode = None

        def poll(self):
            return self.returncode

        def terminate(self):
            self.returncode = 0

        def wait(self, timeout):
            self.returncode = 0
            return 0

    def launch(args, **kwargs):
        command.extend(args)
        for argument in args:
            if argument.endswith(".pid"):
                Path(argument).write_text("43210", encoding="ascii")
        return Process()

    monkeypatch.setattr(native_run, "wsl_path", str)
    monkeypatch.setattr(native_run.subprocess, "Popen", launch)
    monkeypatch.setattr(native_run.subprocess, "run",
                        lambda args, **kwargs: subprocess.CompletedProcess(args, 0))
    monkeypatch.setattr(native_run.urllib.request, "urlopen",
                        lambda *args, **kwargs: nullcontext(SimpleNamespace(status=200)))
    config = tmp_path / "runtime.json"
    config.write_text(json.dumps({"model_sha256": "a" * 64}), encoding="utf-8")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with governed_server(binary=tmp_path / "server", model=tmp_path / "model", config=config,
                         port=port, api_key="test", wsl=wsl, gpu_layers=gpu_layers):
        assert command[command.index("--n-gpu-layers") + 1] == expected


def test_wsl_cleanup_escalates_linux_signal_before_wrapper_kill(tmp_path, monkeypatch):
    from tn_governed import native_run

    events = []
    pid_path = tmp_path / "owned.pid"
    pid_path.write_text("43210", encoding="ascii")

    class Process:
        returncode = None

        def poll(self):
            return self.returncode

        def wait(self, timeout):
            events.append("wait")
            if self.returncode is None:
                raise subprocess.TimeoutExpired("owned-wrapper", timeout)
            return self.returncode

        def kill(self):
            events.append("wrapper-kill")
            self.returncode = -1

    def signal(args, **kwargs):
        assert args[-1] == "43210"
        events.append(args[-3])
        if args[-3] == "-TERM":
            raise subprocess.TimeoutExpired("owned-linux-signal", kwargs["timeout"])
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(native_run.subprocess, "run", signal)
    native_run._stop_owned_server(Process(), wsl=True, pid_path=pid_path)
    assert events.index("-TERM") < events.index("-KILL") < events.index("wrapper-kill")


@pytest.mark.parametrize("pid", ["", "1", "-3", "43210\n54321", "all", "١٢٣"])
def test_wsl_cleanup_never_signals_an_invalid_pid(tmp_path, monkeypatch, pid):
    from tn_governed import native_run

    pid_path = tmp_path / "owned.pid"
    pid_path.write_text(pid, encoding="utf-8")
    process = SimpleNamespace(poll=lambda: None, terminate=lambda: None,
                              wait=lambda timeout: 0)
    monkeypatch.setattr(native_run.subprocess, "run",
                        lambda *args, **kwargs: pytest.fail("unowned Linux process signaled"))
    native_run._stop_owned_server(process, wsl=True, pid_path=pid_path)
