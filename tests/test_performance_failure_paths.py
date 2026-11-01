"""Measurement failures retain their original cause and cannot report success."""

import json
from types import SimpleNamespace

import pytest
from test_endpoints import endpoints as endpoints


def test_tool_tape_export_failure_clears_success_flags(endpoints, tmp_path, monkeypatch):
    from experiments.pvldb_evaluation.performance_tools import measure_chain

    peers, policies = endpoints
    endpoint = peers["source"]
    source = endpoint.originate("synthetic draft", policies=policies[:2])

    def unavailable(directory):
        raise OSError("tape destination unavailable")

    monkeypatch.setattr(endpoint.recorder, "export", unavailable)
    directory = tmp_path / "tool-chain"
    result = measure_chain(endpoint, source, 1, directory)
    assert result["completed"] is False
    assert result["verified"] is False
    assert result["error_type"] == "OSError"
    assert result["tool_seconds"] > 0
    assert result["signed_records"] > 0
    assert json.loads((directory / "measurement.json").read_text()) == result


def test_tool_callback_retains_original_required_action_failure(tmp_path, monkeypatch):
    from experiments.pvldb_evaluation import performance, performance_tools, run

    failure = {
        "completed": False,
        "verified": False,
        "processing_seconds": 0.125,
        "error_type": "OperationDenied",
    }

    def refused_chain(*args):
        return dict(failure)

    def failed_case(directory, mode, **options):
        report = SimpleNamespace(release=SimpleNamespace(tool_objects=(object(),)))
        completion = options["completion_handler"](None, report, None, directory)
        return {"completed": False, "verified": True, "completion": completion}

    monkeypatch.setattr(performance_tools, "integrate_chain", refused_chain)
    monkeypatch.setattr(run, "run_case", failed_case)
    arguments = SimpleNamespace(
        unity_url="http://localhost:18080",
        binary=None,
        plain_binary=None,
        model_path=None,
        port=18325,
    )
    profile = {
        "tool_depths": [3],
        "warmups": 0,
        "repetitions": 1,
        "tool_rows": 1,
        "model": True,
        "sql_batch_size": 256,
    }
    root = tmp_path / "tools"
    with pytest.raises(RuntimeError, match="tool workload failed"):
        performance.run_tool_workloads(root, arguments, profile)
    observations = [json.loads(line) for line in (root / "samples.jsonl").read_text().splitlines()]
    assert len(observations) == 1
    assert observations[0]["ok"] is False
    completion = observations[0]["summary"]["completion"]
    assert completion["error_type"] == "OperationDenied"
    assert completion["native_tool_count"] == 1
    assert completion["completed"] is False and completion["verified"] is False
    assert json.loads((root / "results.json").read_text())["completed"] is False
