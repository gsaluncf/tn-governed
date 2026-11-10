"""The governed-path command takes its API key from the environment and contains TN state."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tn_governed import cli as cli_module
from tn_governed import native_run


def governed_path_arguments(tmp_path: Path) -> list[str]:
    return [
        "governed-path",
        "--run-directory", str((tmp_path / "run").resolve()),
        "--server-binary", str(tmp_path / "llama-server"),
        "--model", str(tmp_path / "model.gguf"),
    ]


def test_cli_uses_env_only_key_and_restores_containment_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    sentinel = "cli-key-must-not-print"
    monkeypatch.setenv("TN_LLAMA_API_KEY", sentinel)
    monkeypatch.setenv("PYTHONDONTWRITEBYTECODE", "previous-bytecode")
    monkeypatch.setenv("TN_NO_LINK", "previous-link")
    monkeypatch.delenv("TN_NO_STDOUT", raising=False)
    monkeypatch.setenv("TN_AUTOINIT_QUIET", "previous-quiet")
    observed = []

    def fake_run(**arguments):
        observed.append(arguments)
        for name in ("PYTHONDONTWRITEBYTECODE", "TN_NO_LINK", "TN_NO_STDOUT", "TN_AUTOINIT_QUIET"):
            assert os.environ[name] == "1"
        return tmp_path / "report.html", tmp_path / "summary.json"

    monkeypatch.setattr(native_run, "run_native_reference", fake_run)
    assert cli_module.main(governed_path_arguments(tmp_path)) == 0
    assert observed[0]["api_key"] == sentinel
    assert observed[0]["port"] == 18280
    assert os.environ["PYTHONDONTWRITEBYTECODE"] == "previous-bytecode"
    assert os.environ["TN_NO_LINK"] == "previous-link"
    assert "TN_NO_STDOUT" not in os.environ
    assert os.environ["TN_AUTOINIT_QUIET"] == "previous-quiet"
    printed = capsys.readouterr()
    assert sentinel not in printed.out + printed.err
    assert "Verified report:" in printed.out


def test_cli_refuses_missing_key_and_has_no_api_key_argument(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("TN_LLAMA_API_KEY", raising=False)
    with pytest.raises(SystemExit):
        cli_module.main(governed_path_arguments(tmp_path))
    assert "TN_LLAMA_API_KEY" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        cli_module.main([*governed_path_arguments(tmp_path), "--api-key", "must-not-be-accepted"])
    assert "--api-key" in capsys.readouterr().err
