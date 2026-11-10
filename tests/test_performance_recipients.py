"""Recipient measurements retain endpoint isolation and failed attempts."""

import hashlib
import importlib
import io
import json
import multiprocessing
import shutil
import zipfile

import pytest
import tn
from test_sql_query_results import database as database
from test_sql_query_results import sql_endpoint as sql_endpoint

from experiments.paper_evaluation.case_study import handle
from tn_governed.values.sql import source_identity


@pytest.fixture
def retained_source(sql_endpoint, tmp_path):
    endpoint = sql_endpoint
    rows = endpoint.driver.execute("SELECT id, amount FROM orders LIMIT 1").fetchall()
    context = endpoint.contexts["consumer"]
    with context:
        value = rows[0][0].as_string() + ": " + rows[0][1].as_string()
        value = value.attest("The amounts are synthetic.", context)
    root = tmp_path / "retained"
    root.mkdir()
    shutil.copytree(endpoint.paths["catalog"].parent, root / "sessions" / "catalog")
    shutil.copytree(endpoint.store.root, root / "publications")
    catalog = endpoint.resolvers["catalog"]
    manifest = {
        "schema": "tn.primitive-run.v1",
        "authority": catalog.session.did,
        "writers": [item.session.did for item in endpoint.contexts.values()],
        "audit_policy": context.recorder.policy.fields,
        "administration_policy": catalog.administration.fields,
        "assignment_id": endpoint.driver.executions[-1]["assignment_id"],
        "source": source_identity(endpoint.driver.database),
        "source_editions": endpoint.driver.editions,
        "request": {"actor": "analyst", "application": "analytics", "purpose": "internal"},
        "outputs": {"model_input": handle(value)},
        "console_disclosures": {"internal": "1: 4"},
        "sources": [handle(item) for item in endpoint.driver.published_values],
        "evaluation": {"rows": 1},
    }
    (root / "run.json").write_text(json.dumps(manifest), encoding="utf-8")
    return root


def test_recipients_have_distinct_signing_identities_kits_and_stores(retained_source, tmp_path):
    module = importlib.import_module("experiments.paper_evaluation.performance_source")
    source_state = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (retained_source / "sessions" / "catalog" / "keys").iterdir()
    }
    roots = module.prepare_recipients(retained_source, tmp_path / "readers", 2)
    identities, kits, stores = [], [], []
    for root in roots:
        archive = root / "publications"
        before = {path.relative_to(archive): path.read_bytes()
                  for path in archive.rglob("*") if path.is_file()}
        with module.open_recipient(root) as recipient:
            identities.append(recipient["session"].did)
            stores.append(recipient["store"])
            assert not hasattr(recipient["store"], "root")
            kits.append((root / "session" / "keys" / "values.btn.mykit").read_bytes())
            assert recipient["value"].reveal(
                recipient["context"], destination="support-console"
            ) == "1: 4"
            assert recipient["context"]._metadata(recipient["value"])[2][0].statement == (
                "The amounts are synthetic."
            )
        assert before == {path.relative_to(archive): path.read_bytes()
                          for path in archive.rglob("*") if path.is_file()}
    assert len(set(identities)) == len(set(kits)) == len(set(stores)) == 2
    assert not (retained_source / "recipient.json").exists()
    assert source_state == {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (retained_source / "sessions" / "catalog" / "keys").iterdir()
    }


def test_recipient_rejects_changed_identity_checkpoint(retained_source, tmp_path):
    module = importlib.import_module("experiments.paper_evaluation.performance_source")
    root = module.prepare_recipient(retained_source, tmp_path / "reader")
    path = root / "recipient.json"
    checkpoint = json.loads(path.read_text())
    checkpoint["identity"] = "did:key:another-endpoint"
    path.write_text(json.dumps(checkpoint), encoding="utf-8")
    with pytest.raises(ValueError, match="identity"), module.open_recipient(root):
        pytest.fail("changed endpoint identity was accepted")


def test_recipient_rejects_changed_workload_manifest(retained_source, tmp_path):
    module = importlib.import_module("experiments.paper_evaluation.performance_source")
    root = module.prepare_recipient(retained_source, tmp_path / "reader")
    path = root / "run.json"
    manifest = json.loads(path.read_text())
    manifest["console_disclosures"]["internal"] = "substituted workload"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="manifest"), module.open_recipient(root):
        pytest.fail("changed source checkpoint was accepted")


def test_dataframe_recipient_admits_complete_signed_evaluator_artifacts(tmp_path, monkeypatch):
    from tn_polars.registry import UnityCatalogRegistry
    from tn_polars.release import PolicyDenied

    from experiments.paper_evaluation.performance_source import open_recipient, prepare_recipient
    from experiments.paper_evaluation.run import run_case

    volumes = {}

    def request(self, method, path, payload=None):
        if path in {"/catalogs", "/schemas"}:
            return {}
        if method == "POST" and path == "/volumes":
            name = f"{payload['catalog_name']}.{payload['schema_name']}.{payload['name']}"
            volumes[name] = dict(payload)
            return volumes[name]
        if method == "GET" and path.startswith("/volumes/"):
            return volumes[path.removeprefix("/volumes/")]
        raise AssertionError((method, path))

    monkeypatch.setattr(UnityCatalogRegistry, "_request", request)
    source = tmp_path / "dataframe-source"
    import os
    result = run_case(source, "primitive", rows=2, claim=True,
                      sdk_build_record=os.getenv("TN_TEST_SDK_BUILD_RECORD"))
    assert result["completed"] and result["verified"], result
    root = prepare_recipient(source, tmp_path / "dataframe-recipient")
    with open_recipient(root) as recipient:
        value, context = recipient["value"], recipient["context"]
        opened = value.reveal(context, destination=recipient["destination"])
        assert opened == result["expected_content"]
        from experiments.paper_evaluation.performance_recipients import _check_disclosures, _request
        observations = [_request(recipient)]
        damaged = [{**observations[0], "released_content": "wrong"}]
        _check_disclosures(observations, opened)
        _check_disclosures(damaged, opened)
        assert observations[0]["status"] == "completed" and "released_content" not in observations[0]
        assert damaged[0]["failure_stage"] == "verification" and "released_content" not in damaged[0]
        data, _, claims = context._metadata(value)
        assert len(data.policies) == 2 and len(claims) == 1
        assert len(context.editions) == 2
        current = recipient["manifest"]
        assert "console_disclosures" not in current and "evaluation" not in current
        expected = json.loads((source / "run.json").read_text())["recipient_objects"]
        from tn_governed.publications import open_publication_store
        with open_publication_store(root / "publications", read_only=True) as delivered:
            transferred = set(delivered.publication_sizes())
        assert transferred == set(expected)
        assert all(info["source_object_id"] not in transferred for info in current["source_editions"])
    bundle = next((root / "editions").glob("*/*/bundle.zip"))
    with zipfile.ZipFile(bundle) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    artifact = next(name for name in files if name.endswith("/data.json"))
    files[artifact] = b'{"substituted":true}'
    with zipfile.ZipFile(bundle, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    with pytest.raises(PolicyDenied, match="digest"), open_recipient(root):
        pytest.fail("changed evaluator artifact was admitted")


def test_summary_counts_failures_and_uses_round_wall_time():
    module = importlib.import_module("experiments.paper_evaluation.performance_recipients")
    rounds = [
        {"warmup": True, "wall_ns": 1, "requests": [
            {"status": "completed", "elapsed_ns": 1}]},
        {"warmup": False, "wall_ns": 4_000_000_000, "requests": [
            {"status": "completed", "elapsed_ns": 1_000_000_000},
            {"status": "completed", "elapsed_ns": 3_000_000_000}]},
        {"warmup": False, "wall_ns": 2_000_000_000, "requests": [
            {"status": "failed", "elapsed_ns": 2_000_000_000},
            {"status": "completed", "elapsed_ns": 1_000_000_000}]},
    ]
    summary = module.summarize_rounds(rounds)
    assert summary["attempts"] == 4
    assert summary["completed"] == 3
    assert summary["failed"] == 1
    assert summary["median_ms"] == 1000
    assert summary["p95_ms"] == 3000
    assert summary["throughput_per_second"] == 0.5


def test_spawned_recipients_verify_and_sign_each_request(retained_source, tmp_path):
    module = importlib.import_module("experiments.paper_evaluation.performance_recipients")
    result = module.run_recipients(retained_source, tmp_path / "concurrent", 2, 1, 1)
    assert result["status"] == "completed", result
    assert len({worker["pid"] for worker in result["workers"]}) == 2
    assert len({worker["identity"] for worker in result["workers"]}) == 2
    assert result["summary"]["attempts"] == result["summary"]["completed"] == 2
    assert len(result["rounds"]) == 2
    records = []
    for row in result["rounds"]:
        assert row["wall_ns"] > 0
        for request in row["requests"]:
            assert request["elapsed_ns"] > 0
            assert request["signed_records"] == 3
            assert len(request["record_publications"]) == request["signed_records"]
            for identity, wire in zip(
                request["record_ids"], request["record_publications"], strict=True,
            ):
                publication = tn.GovernedObject.read(io.BytesIO(wire.encode("utf-8")))
                assert publication.id == identity
                assert publication.writer == request["identity"]
            records.extend(request["record_ids"])
    assert len(set(records)) == len(records) == 12
    assert len((tmp_path / "concurrent" / "rounds.jsonl").read_text().splitlines()) == 2


def test_invalid_source_is_retained_as_preflight_failure(tmp_path):
    module = importlib.import_module("experiments.paper_evaluation.performance_recipients")
    result = module.run_recipients(tmp_path / "missing", tmp_path / "output", 1, 1, 0)
    assert result["status"] == "failed"
    assert result["error_type"] == "FileNotFoundError"
    assert result["summary"]["attempts"] == 0
    assert json.loads((tmp_path / "output" / "result.json").read_text()) == result


@pytest.mark.parametrize("closed", [True, False])
def test_partial_worker_results_survive_disconnect_or_timeout(closed):
    module = importlib.import_module("experiments.paper_evaluation.performance_recipients")
    parent_a, child_a = multiprocessing.Pipe()
    parent_b, child_b = multiprocessing.Pipe()
    try:
        child_a.send({"status": "completed", "elapsed_ns": 10})
        if closed:
            child_b.close()
        result = module._collect([parent_a, parent_b], timeout=0.02)
        assert result[0] == {"status": "completed", "elapsed_ns": 10}
        assert result[1]["status"] == "failed"
        assert result[1]["elapsed_ns"] is None
        assert result[1]["failure_stage"] == "worker_response"
        assert result[1]["error_type"] == ("EOFError" if closed else "TimeoutError")
    finally:
        for connection in (parent_a, child_a, parent_b, child_b):
            connection.close()


@pytest.mark.parametrize("concurrency,repetitions,warmups", [(0, 1, 0), (1, 0, 0), (1, 1, -1)])
def test_invalid_schedule_does_not_create_output(tmp_path, concurrency, repetitions, warmups):
    module = importlib.import_module("experiments.paper_evaluation.performance_recipients")
    output = tmp_path / "output"
    with pytest.raises(ValueError):
        module.run_recipients(tmp_path, output, concurrency, repetitions, warmups)
    assert not output.exists()
