import json
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments.paper_evaluation import performance_model
from tn_governed import native_run


@pytest.mark.parametrize("kind", ["governed", "ordinary"])
@pytest.mark.parametrize("inherited_config", [None, "/shared/user-config"])
def test_native_linux_process_uses_absolute_per_run_config(
    tmp_path, monkeypatch, kind, inherited_config
):
    module = native_run if kind == "governed" else performance_model
    environment = {"HOME": "/shared/home", "APPDATA": "/shared/windows-config"}
    if inherited_config is not None:
        environment["XDG_CONFIG_HOME"] = inherited_config
    monkeypatch.setattr(module, "os", SimpleNamespace(name="posix", environ=environment))
    monkeypatch.chdir(tmp_path)
    launches = []

    class Process:
        returncode = None

        def poll(self):
            return self.returncode

        def terminate(self):
            self.returncode = 0

        def wait(self, timeout):
            return self.returncode

    class Socket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def settimeout(self, timeout):
            pass

        def setsockopt(self, level, option, value):
            pass

        def connect_ex(self, address):
            return 111

        def bind(self, address):
            pass

    def launch(arguments, **kwargs):
        launches.append(kwargs["env"])
        assert kwargs["creationflags"] == 0
        return Process()

    monkeypatch.setattr(module.socket, "socket", Socket)
    monkeypatch.setattr(module.subprocess, "Popen", launch)
    monkeypatch.setattr(
        module.urllib.request,
        "urlopen",
        lambda *args, **kwargs: nullcontext(SimpleNamespace(status=200)),
    )
    for run_name in ("first-run", "second-run"):
        directory = Path(run_name)
        directory.mkdir()
        if kind == "governed":
            config = directory / "runtime.json"
            config.write_text(json.dumps({"model_sha256": "a" * 64}), encoding="utf-8")
            server = native_run.governed_server(
                binary=tmp_path / "server",
                model=tmp_path / "model.gguf",
                config=config,
                port=19381,
                api_key="test-key",
            )
        else:
            server = performance_model.ordinary_server(
                directory,
                binary=tmp_path / "server",
                model=tmp_path / "model.gguf",
                port=19381,
            )
        with server:
            expected = str((directory / "server-config-root").resolve())
            assert launches[-1].get("XDG_CONFIG_HOME") == expected
            assert launches[-1]["APPDATA"] == expected
            assert launches[-1]["PROGRAMDATA"] == expected
            assert Path(expected).is_dir()
    assert launches[0]["XDG_CONFIG_HOME"] != launches[1]["XDG_CONFIG_HOME"]
    assert environment.get("XDG_CONFIG_HOME") == inherited_config
