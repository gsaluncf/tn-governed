"""Dependent tool measurements retain signed decisions and source attribution."""

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from test_endpoints import endpoints as endpoints
from test_performance_recipients import retained_source as retained_source
from test_sql_query_results import database as database
from test_sql_query_results import sql_endpoint as sql_endpoint


@pytest.mark.parametrize("depth", [1, 3, 5])
def test_measured_tool_chain_verifies_dependency_depth_and_required_action(
    endpoints,
    tmp_path,
    depth,
):
    from experiments.pvldb_evaluation.performance_tools import measure_chain

    peers, policies = endpoints
    endpoint = peers["source"]
    source = endpoint.attest(
        endpoint.originate("ACME: 1501 demonstration cents", policies=policies[:2]),
        "The calculation uses synthetic observations.",
    )
    claim = endpoint.claims(source)[0]
    result = measure_chain(endpoint, source, depth, tmp_path / "measurement")
    assert result["completed"] and result["verified"]
    assert result["observed_depth"] == depth
    assert len(result["calls"]) == depth
    assert result["claims"] == [claim.id]
    assert result["policy_count"] == 2
    assert result["tool_seconds"] > 0
    assert result["signed_records"] > 0
    assert result["added_native_bytes"] > 0
    assert result["receipt_count"] == depth
    assert result["required_action_count"] == 1
    assert result["required_action_record_id"] in result["action_records"]
    output = json.loads((tmp_path / "measurement" / "measurement.json").read_text())
    assert output == result
    for index, call in enumerate(result["calls"]):
        assert call["dependencies"] == ([] if index == 0 else [result["calls"][index - 1]["id"]])
        assert endpoint.read_record(call["result_id"]).body["kind"] == "Result"


def test_invalid_tool_schedule_does_not_create_measurement_directory(tmp_path):
    from experiments.pvldb_evaluation.tool_study import run_tools

    output = tmp_path / "measurements"
    for depths, repetitions, warmups in [([0], 1, 0), ([1, 1], 1, 0), ([1], 0, 0), ([1], 1, -1)]:
        with pytest.raises(ValueError):
            run_tools(tmp_path / "absent", output, depths, repetitions, warmups)
    assert not output.exists()


def test_tool_summary_excludes_warmups_and_retains_failures():
    from experiments.pvldb_evaluation.tool_study import summarize_tools

    cases = [
        {
            "depth": 1,
            "warmup": True,
            "completed": True,
            "verified": True,
            "tool_seconds": 900,
            "signed_records": 10,
            "added_native_bytes": 20,
        },
        {
            "depth": 1,
            "warmup": False,
            "completed": True,
            "verified": True,
            "tool_seconds": 2,
            "signed_records": 10,
            "added_native_bytes": 20,
        },
        {
            "depth": 1,
            "warmup": False,
            "completed": False,
            "verified": False,
            "error_type": "RuntimeError",
        },
        {
            "depth": 3,
            "warmup": False,
            "completed": True,
            "verified": True,
            "tool_seconds": 6,
            "signed_records": 30,
            "added_native_bytes": 60,
        },
    ]
    summary = summarize_tools(cases)
    assert summary[0]["attempts"] == 2
    assert summary[0]["successful"] == 1
    assert summary[0]["median_tool_seconds"] == 2
    assert summary[0]["failures"] == 1
    assert summary[1]["tool_overhead_vs_depth_1"] is None
    complete = summarize_tools([case for case in cases if case["completed"]])
    assert complete[1]["tool_overhead_vs_depth_1"] == 3


def test_required_action_failure_is_retained_without_reporting_verified_result(endpoints, tmp_path):
    from experiments.pvldb_evaluation.performance_tools import measure_chain
    from tn_governed.values.runtime import Assessment, ObligationResult

    peers, policies = endpoints
    endpoint = peers["source"]
    source = endpoint.originate("draft", policies=policies[:2])
    endpoint.evaluator = lambda request: Assessment(
        True,
        "requires queue",
        ("unavailable",) if request.operation == "workflow.release" else (),
    )
    endpoint.obligations["unavailable"] = lambda _: ObligationResult(False, "")
    result = measure_chain(endpoint, source, 1, tmp_path / "failed")
    assert result["completed"] is False and result["verified"] is False
    assert result["error_type"] == "OperationDenied"
    assert result["tool_seconds"] > 0
    assert json.loads((tmp_path / "failed" / "measurement.json").read_text()) == result
    assert endpoint.records()[-1].body["kind"] == "Refusal"


def test_retained_scalar_import_preserves_source_and_measures_separate_tool_trials(
    retained_source,
    tmp_path,
):
    from experiments.pvldb_evaluation.tool_study import run_tools

    (retained_source / "case-summary.json").write_text(
        json.dumps(
            {
                "completed": True,
                "verified": True,
                "rows": 1,
                "with_model": False,
                "timings_seconds": {},
            }
        )
    )
    source_before = (retained_source / "run.json").read_bytes()
    result = run_tools(retained_source, tmp_path / "tools", [1], 1, 1)
    assert result["completed"]
    assert result["source_with_model"] is False
    assert result["source_timings_seconds"] == {}
    assert [case["warmup"] for case in result["cases"]] == [True, False]
    assert result["aggregates"][0]["successful"] == 1
    assert all(case["claims"] for case in result["cases"])
    assert (retained_source / "run.json").read_bytes() == source_before


def test_integrated_chain_admits_scalar_inside_its_processing_interval(sql_endpoint, tmp_path):
    from experiments.pvldb_evaluation.performance_tools import integrate_chain

    context = sql_endpoint.contexts["consumer"]
    rows = sql_endpoint.driver.execute("SELECT id, amount FROM orders LIMIT 1").fetchall()
    with context:
        source = rows[0][0].as_string() + ": " + rows[0][1].as_string()
        source = source.attest("Synthetic calculation", context)
    result = integrate_chain(context, None, source, 1, tmp_path / "integrated")
    assert result["completed"] and result["verified"]
    assert result["bridge_seconds"] > 0
    assert result["processing_seconds"] == result["bridge_seconds"] + result["tool_seconds"]
    assert result["integrated_signed_records"] > result["signed_records"]
    assert result["claims"] == [context._metadata(source)[2][0].id]
    assert result["native_report_id"] is None


def _accepted_native_report(context, source):
    from tn_governed.publications import write_once
    from tn_governed.values.model import NativeReport, ReviewRequest

    store = context.recorder.store
    policies = context._metadata(source)[0].policies
    claims = context._metadata(source)[2]
    html = "<p>ACME: synthetic report requiring review.</p>"
    publication = context.session.create(
        {"report_html": html},
        policies[0],
        object_type="report.generated",
        group="values",
    ).snapshot
    tool = context.session.create(
        {"receipt": "logged"},
        policies[0],
        object_type="tool.completed",
        group="values",
    ).snapshot
    for item in (publication, tool):
        store.put(item)
    arguments = {
        "call_id": "accepted-model-invocation",
        "application": context.application,
        "purpose": context.purpose,
        "operation": "model_handoff",
        "inputs": (source.reference,),
        "destination": "internal-model",
    }
    decision = context.recorder.append("Decision", **arguments, details={"permitted": True})
    handoff = context.recorder.append(
        "ModelHandoff",
        **arguments,
        details={
            "decision_id": decision,
            "subject": source.reference.to_dict(),
            "delivery": "prepared-for-submit",
            "input_wire_sha256": hashlib.sha256(store.get(source.reference.object_id)).hexdigest(),
        },
    )
    digest = hashlib.sha256(html.encode()).hexdigest()
    review_id = context.recorder.append(
        "ReviewRequested",
        **arguments,
        details={
            "decision_id": decision,
            "handoff_record_id": handoff,
            "input_object_id": source.reference.object_id,
            "report_object_id": publication.id,
            "report_html_sha256": digest,
            "status": "pending",
            "review_action": {
                "action": "human_review",
                "assignee": "review-team",
                "reason": "draft",
            },
        },
    )
    entry = "review-queue/" + review_id[7:] + ".tn"
    write_once(store.root.parent / entry, store.get(review_id))
    result = context.recorder.append(
        "ModelResult",
        **arguments,
        details={
            "decision_id": decision,
            "handoff_record_id": handoff,
            "input_object_id": source.reference.object_id,
            "output_object_id": publication.id,
            "report_html_sha256": digest,
            "tool_object_ids": [tool.id],
            "review_request_id": review_id,
            "claims": [claim.id for claim in claims],
        },
    )
    return NativeReport(
        publication,
        html,
        SimpleNamespace(output_object=publication, tool_objects=(tool,)),
        decision,
        handoff,
        result,
        ReviewRequest(review_id, publication.id, "pending", "review-team", "draft", entry),
    )


def test_integrated_report_retains_signed_acceptance_and_rejects_changed_html(
    sql_endpoint, tmp_path
):
    from experiments.pvldb_evaluation.performance_tools import integrate_chain
    from tn_governed.values.evidence import EvidenceError

    context = sql_endpoint.contexts["consumer"]
    rows = sql_endpoint.driver.execute("SELECT id, amount FROM orders LIMIT 1").fetchall()
    with context:
        source = rows[0][0].as_string() + ": " + rows[0][1].as_string()
        source = source.attest("Synthetic calculation", context)
    report = _accepted_native_report(context, source)
    result = integrate_chain(context, report, source, 1, tmp_path / "report-chain")
    assert result["completed"] and result["verified"]
    assert result["native_report_id"] == report.object.id
    bridge = context.recorder.store.read(result["bridge_artifact"]["reference"]["object_id"])
    opened = context.session.receive(
        bridge,
        use=__import__("tn").UseContext("tool-performance", "internal-review", "inspect"),
        groups=["values", "evidence"],
        decide=lambda _: True,
    )
    evidence = opened.get("manifest", group="evidence")["parameters"]["accepted_native_report"]
    assert evidence["report_html_sha256"] == hashlib.sha256(report.report_html.encode()).hexdigest()
    assert report.object.forward().decode() in evidence["native_publications"]
    assert (
        context.recorder.store.get(report.result_record_id).decode()
        in evidence["acceptance_records"]
    )
    with pytest.raises(EvidenceError, match="signed invocation"):
        integrate_chain(
            context,
            replace(report, report_html="<p>changed</p>"),
            source,
            1,
            tmp_path / "tampered-chain",
        )
    queue = context.recorder.store.root.parent / report.review.queue_entry
    queue.write_bytes(b"changed")
    with pytest.raises(EvidenceError, match="signed registration"):
        integrate_chain(context, report, source, 1, tmp_path / "tampered-queue")


def test_tool_enrollment_failures_are_retained_in_raw_cases(monkeypatch, tmp_path):
    from experiments.pvldb_evaluation import performance_source
    from experiments.pvldb_evaluation.tool_study import run_tools

    source = tmp_path / "source"
    source.mkdir()
    (source / "case-summary.json").write_text(
        json.dumps(
            {
                "completed": True,
                "verified": True,
                "rows": 1,
                "with_model": False,
                "timings_seconds": {},
            }
        )
    )

    def unavailable(*args):
        raise RuntimeError("reader material unavailable")

    monkeypatch.setattr(performance_source, "prepare_recipient", unavailable)
    output = tmp_path / "measurements"
    result = run_tools(source, output, [1], 2, 0)
    assert result["completed"] is False
    assert result["aggregates"][0]["failures"] == 2
    assert len((output / "observations.jsonl").read_text().splitlines()) == 2
    assert all(case["error_stage"] == "enrollment" for case in result["cases"])
    assert json.loads((output / "measurements.json").read_text()) == result
