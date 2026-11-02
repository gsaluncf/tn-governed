"""Retained native context binds each decision to its admitted source and task."""

import base64
import copy
import hashlib
import json

import pytest

from tn_governed.witness import verify_reference_run


def encoded(raw):
    return base64.b64encode(raw).decode()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def digest(domain, raw):
    return "sha256:" + hashlib.sha256(domain.encode() + b"\0" + raw).hexdigest()


@pytest.fixture
def context_records():
    source = "sha256:" + "a" * 64
    request = "sha256:" + "b" * 64
    audit, trace = [], []

    def event(kind, facts, task=None):
        row = {
            "kind": kind,
            "run_id": "run-context",
            "request_digest": request,
            "target_row_hash": source,
            "llama_task_id": task,
            "llama_slot_id": 0 if task is not None else None,
            "outcome": "allow",
            "facts_json": json.dumps(facts),
            "sequence": len(audit),
        }
        audit.append(row)

    event(
        "governance_opened_and_verified",
        {
            "governance_context_protocol": "tn.llama.governance-context.v1",
            "source_row_hash": source,
            "hashes_verified": True,
            "governance_value_count": 2,
            "governance_commitment_count": 2,
        },
    )
    for task, phase in [(31, 3), (41, 4), (42, 4)]:
        context = {
            "policy": {"attribution": "Show the source", "extension": {"scope": ["a", "b"]}},
            "claims": [{"issuer": "publisher", "subject": source}],
        }
        if task == 42:
            context["tool_conditions"] = {"attribution": "Show the compliance receipt"}
        control = {
            "phase": "section_selection" if phase == 3 else "governed_action",
            "applicable_source_governance": context,
        }
        body = canonical({"messages": [{"role": "user", "content": canonical(control).decode()}]})
        prompt = b"USER\n" + canonical(control) + b"\nASSISTANT\n"
        manifest = canonical(
            {"schema": "tn.llama.runnable-task.v1", "task": {"tokens": [1, task, 12]}}
        )
        facts = {
            "phase": phase,
            "turn_ordinal": phase,
            "source_row_hash": source,
            "context_digest": digest("tn.llama.governance-context.v1", canonical(context)),
            "model_request_digest": digest("tn.llama.model-request.v1", body),
            "rendered_prompt_digest": digest("tn.llama.rendered-prompt.v1", prompt),
            "runnable_task_digest": digest("tn.llama.runnable-task.v1", manifest),
        }
        event("governance_context_bound", facts, task)
        event("turn_begin_authorized", facts, task)
        for kind in ["turn_prepared", "turn_started", "model_result"]:
            trace.append(
                {
                    "kind": kind,
                    "run_id": "run-context",
                    "phase": phase,
                    "sequence": len(trace),
                    "task_id": None if kind == "turn_prepared" else task,
                    "slot_id": None if kind == "turn_prepared" else 0,
                    "request_json_b64": encoded(body) if kind != "model_result" else None,
                    "rendered_prompt_b64": encoded(prompt) if kind != "model_result" else None,
                    "runnable_manifest_b64": encoded(manifest) if kind != "model_result" else None,
                    "raw_model_output_b64": encoded(b"tool response")
                    if kind == "model_result"
                    else None,
                }
            )
    event("output_emitted_and_read_back", facts, 42)
    event("source_chain_committed", facts, 42)
    trace.append(
        {
            "kind": "release",
            "run_id": "run-context",
            "phase": 4,
            "sequence": len(trace),
            "task_id": 42,
            "slot_id": 0,
            "parsed_content_b64": encoded(canonical({
                "protocol": "tn.llama.release.v1",
                "run_id": "run-context",
                "source_event_id": "source-event",
                "source_row_hash": source,
                "output_event_id": "output-event",
                "output_row_hash": "sha256:" + "c" * 64,
                "trace": [
                    {
                        "ordinal": index,
                        "event": event,
                        "state": "complete" if event == "release" else "governed_action",
                        "task_id": 42,
                        "slot_id": 0,
                        "row_hash": "sha256:" + "c" * 64,
                        "event_id": "output-event",
                    }
                    for index, event in enumerate(("output_readback", "release"))
                ],
            })),
        }
    )
    return audit, trace


def write_rows(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def retain_release_actions(audit, trace):
    release = json.loads(base64.b64decode(trace[-1]["parsed_content_b64"]))
    actions = []
    events = {
        "sections_selected": "sections_selected",
        "sections_selected_runtime": "sections_selected_runtime",
        "governed_tool_executed": "tool_executed",
        "governed_tool_executed_runtime": "tool_executed_runtime",
    }
    for row in audit:
        if row["kind"] not in events:
            continue
        tool = row["kind"].startswith("governed_tool")
        item = {
            "event": events[row["kind"]],
            "state": "governed_action",
            "task_id": row.get("llama_task_id"),
            "slot_id": row.get("llama_slot_id"),
            "row_hash": "sha256:" + "e" * 64 if tool else row["target_row_hash"],
            "event_id": "receipt-event" if tool else None,
            "tool_name": "record_review" if tool else None,
            "selected_sections": ["values"],
        }
        actions.append(item)
        if tool:
            actions.append({**item, "event": "receipt_inserted"})
    release["trace"] = actions + [
        item for item in release["trace"] if item["event"] in {"output_readback", "release"}
    ]
    for ordinal, item in enumerate(release["trace"]):
        item["ordinal"] = ordinal
    trace[-1]["parsed_content_b64"] = encoded(canonical(release))


@pytest.fixture
def reference_run(tmp_path, context_records):
    audit, trace = context_records
    source_hash = audit[0]["target_row_hash"]
    output_hash = "sha256:" + "c" * 64
    policy = "https://policy.test/rules#sha256:" + "d" * 64
    summary = {
        "tn_handoffs": {
            "model_source_event_id": "source-event",
            "model_source_row_hash": source_hash,
            "policy_reference": policy,
        },
        "verified_output": {"event_id": "output-event", "row_hash": output_hash},
        "calculation": {"invocation_count": 1},
    }
    (tmp_path / "run-summary.json").write_text(json.dumps(summary), encoding="utf-8")
    actions = {
        31: "sections_selected",
        41: "governed_tool_executed",
    }
    with_actions = []
    for row in audit:
        with_actions.append(row)
        if row["kind"] == "turn_begin_authorized" and row["llama_task_id"] in actions:
            with_actions.append({**row, "kind": actions[row["llama_task_id"]]})
    audit = with_actions
    audit.append(
        {
            "kind": "row_verified",
            "outcome": "allow",
            "facts_json": json.dumps({"signature_verified": True}),
        }
    )
    for sequence, row in enumerate(audit):
        row["sequence"] = sequence
    retain_release_actions(audit, trace)
    request = {
        "protocol": "tn.llama.request.v1",
        "purpose": "derived_html_report",
        "messages": [{"role": "user", "content": "Explain the calculation."}],
    }
    request_hash = digest(
        "tn.llama.request-context.v1",
        canonical(
            {
                "messages": request["messages"],
                "purpose": request["purpose"],
                "row_hash": source_hash,
            }
        ),
    )
    for row in audit:
        if "request_digest" in row:
            row["request_digest"] = request_hash
    write_rows(tmp_path / "runtime/decision-events.ndjson", audit)
    write_rows(tmp_path / "runtime/raw-trace/run-context.sensitive.ndjson", trace)
    response = {
        "protocol": "tn.llama.release.v1",
        "run_id": "run-context",
        "source_event_id": "source-event",
        "source_row_hash": source_hash,
        "output_event_id": "output-event",
        "output_row_hash": output_hash,
        "trace": json.loads(base64.b64decode(trace[-1]["parsed_content_b64"]))["trace"],
    }
    client = [
        {
            "peer": "llama",
            "direction": "request",
            "url": "/v1/tn/chat/completions",
            "body_b64": encoded(canonical(request)),
        },
        {
            "peer": "llama",
            "direction": "response",
            "status": 200,
            "body_b64": encoded(canonical(response)),
        },
        {"event": "encrypted_release_verified", "output_row_hash": output_hash},
    ]
    client += [
        {"event": "release_group_opened", "group": group, "signature": True}
        for group in ["tn.agents", "default"]
    ]
    write_rows(tmp_path / "client/http.ndjson", client)
    write_rows(
        tmp_path / "client/received-output.ndjson",
        [{"event_id": "output-event", "row_hash": output_hash}],
    )
    write_rows(
        tmp_path / "tn/calculation/.tn/tn/logs/tn.ndjson",
        [
            {
                "event_id": "source-event",
                "row_hash": source_hash,
                "device_identity": "publisher",
                "tn_aad": json.dumps({"finance": {"policy": policy, "governed_by": "publisher"}}),
            }
        ],
    )
    packages = tmp_path / "tn/packages"
    packages.mkdir(parents=True)
    for name in [
        "source-to-polars",
        "polars-to-calculation",
        "calculation-to-llama",
        "llama-to-report",
    ]:
        (packages / (name + ".tnpkg")).write_bytes(b"retained package")
    return tmp_path


def test_witness_accepts_native_context_for_selection_and_every_action(reference_run):
    result = verify_reference_run(reference_run)
    assert result.all_full, [(item.number, item.status) for item in result.questions]
    assert all("commitments matched" not in item.evidence for item in result.questions)


def inspect(records, **expected):
    from tn_governed.context_evidence import inspect_governance_context

    return inspect_governance_context(
        *records,
        run_id="run-context",
        request_digest="sha256:" + "b" * 64,
        source_id="sha256:" + "a" * 64,
        **expected,
    )


def test_context_reader_retains_variable_semantics_and_all_decision_tasks(context_records):
    result = inspect(context_records)
    assert result.verified
    assert result.protocol == "tn.llama.governance-context.v1"
    assert result.task_ids == (31, 41, 42)
    assert result.phases == (3, 4, 4)


@pytest.mark.parametrize(
    "field,value",
    [
        ("run_id", "other-run"),
        ("request_digest", "sha256:" + "e" * 64),
        ("target_row_hash", "sha256:" + "e" * 64),
        ("llama_task_id", 999),
        ("llama_slot_id", 5),
    ],
)
def test_context_reader_rejects_unrelated_bound_event_identity(context_records, field, value):
    context_records[0][3][field] = value
    assert not inspect(context_records).verified


@pytest.mark.parametrize(
    "field,value",
    [
        ("context_digest", "sha256:" + "e" * 64),
        ("source_row_hash", "sha256:" + "e" * 64),
        ("model_request_digest", "sha256:" + "e" * 64),
        ("rendered_prompt_digest", "sha256:" + "e" * 64),
        ("runnable_task_digest", "sha256:" + "e" * 64),
        ("phase", 3),
    ],
)
def test_context_reader_rejects_altered_binding_facts(context_records, field, value):
    row = context_records[0][3]
    facts = json.loads(row["facts_json"])
    facts[field] = value
    row["facts_json"] = json.dumps(facts)
    assert not inspect(context_records).verified


@pytest.mark.parametrize(
    "kind", ["governance_opened_and_verified", "governance_context_bound", "turn_begin_authorized"]
)
def test_context_reader_requires_admission_and_each_bound_authorization(context_records, kind):
    audit, _ = context_records
    audit.remove(next(row for row in audit if row["kind"] == kind))
    assert not inspect(context_records).verified


@pytest.mark.parametrize(
    "field", ["request_json_b64", "rendered_prompt_b64", "runnable_manifest_b64"]
)
def test_context_reader_rejects_missing_or_altered_execution_artifact(context_records, field):
    context_records[1][4][field] = encoded(b"altered artifact")
    assert not inspect(context_records).verified
    context_records[1][4][field] = None
    assert not inspect(context_records).verified


@pytest.mark.parametrize("kind", ["turn_prepared", "turn_started", "model_result"])
def test_context_reader_requires_each_execution_stage(context_records, kind):
    trace = context_records[1]
    trace.remove(next(row for row in trace if row["kind"] == kind))
    assert not inspect(context_records).verified


def test_context_reader_rejects_admission_after_decision(context_records):
    audit = context_records[0]
    audit.append(audit.pop(0))
    for sequence, row in enumerate(audit):
        row["sequence"] = sequence
    assert not inspect(context_records).verified


def test_context_reader_rejects_result_before_execution(context_records):
    trace = context_records[1]
    trace[1], trace[2] = trace[2], trace[1]
    for sequence, row in enumerate(trace):
        row["sequence"] = sequence
    assert not inspect(context_records).verified


def test_context_reader_does_not_downgrade_missing_bindings_to_echo(context_records):
    audit, trace = context_records
    audit[:] = [row for row in audit if row["kind"] != "governance_context_bound"]
    echo = copy.deepcopy(audit[0])
    echo.update(kind="commitments_matched", sequence=len(audit))
    echo["facts_json"] = json.dumps({"hashes_matched": True, "governance_commitment_count": 2})
    audit.append(echo)
    result = inspect((audit, trace))
    assert not result.verified
    assert result.protocol == "tn.llama.governance-context.v1"


def test_context_reader_reports_retained_echo_protocol_explicitly(context_records):
    admission = copy.deepcopy(context_records[0][0])
    facts = json.loads(admission["facts_json"])
    facts.pop("governance_context_protocol")
    admission["facts_json"] = json.dumps(facts)
    echo = {
        **admission,
        "sequence": 1,
        "kind": "commitments_matched",
        "facts_json": json.dumps({"hashes_matched": True, "governance_commitment_count": 2}),
    }
    result = inspect(([admission, echo], []))
    assert result.protocol == "legacy_echo"
    assert result.verified
    assert result.task_ids == ()


def test_completed_model_observations_reject_an_action_without_context(context_records):
    from tn_governed.values.evidence import EvidenceError
    from tn_governed.values.verify_model import verified_context_observation

    audit, trace = context_records
    audit.remove(audit[3])
    with pytest.raises(EvidenceError, match="governance context"):
        verified_context_observation(
            audit,
            trace,
            run_id="run-context",
            request_digest="sha256:" + "b" * 64,
            source_id="sha256:" + "a" * 64,
        )


def bind_context(records, turn, context):
    """Retain matching digests for a controlled semantic input."""
    audit, trace = records
    start = trace[turn * 3 + 1]
    request = json.loads(base64.b64decode(start["request_json_b64"]))
    control = json.loads(request["messages"][0]["content"])
    control["applicable_source_governance"] = context
    request["messages"][0]["content"] = canonical(control).decode()
    body = canonical(request)
    prompt = b"USER\n" + canonical(control) + b"\nASSISTANT\n"
    for row in trace[turn * 3 : turn * 3 + 2]:
        row["request_json_b64"] = encoded(body)
        row["rendered_prompt_b64"] = encoded(prompt)
    for row in audit:
        if row.get("llama_task_id") != start["task_id"]:
            continue
        facts = json.loads(row["facts_json"])
        facts.update(
            context_digest=digest("tn.llama.governance-context.v1", canonical(context)),
            model_request_digest=digest("tn.llama.model-request.v1", body),
            rendered_prompt_digest=digest("tn.llama.rendered-prompt.v1", prompt),
        )
        row["facts_json"] = json.dumps(facts)


@pytest.fixture
def native_context_records(context_records):
    source_id = "sha256:" + "a" * 64
    for row in context_records[0]:
        facts = json.loads(row["facts_json"])
        facts["source_object_id"] = facts.pop("source_row_hash")
        row["facts_json"] = json.dumps(facts)
    context = {
        "schema": "tn.llama.decision-context.v1",
        "use": {"operation": "report"},
        "destination": "report-reader",
        "claims": [],
        "sources": [
            {
                "object_id": source_id,
                "writer": "publisher",
                "governed_by": "publisher",
                "governance": {"policy": {"required_notice": "Show the source"}},
            }
        ],
    }
    for turn in range(3):
        bind_context(context_records, turn, context)
    for row in context_records[0]:
        if row["kind"] == "source_chain_committed":
            row["kind"] = "standalone_use_completed"
    release = json.loads(base64.b64decode(context_records[1][-1]["parsed_content_b64"]))
    release["protocol"] = "tn.llama.release.v2"
    release["source_object_id"] = release.pop("source_row_hash")
    release["output_object_id"] = release.pop("output_row_hash")
    release.pop("source_event_id")
    release.pop("output_event_id")
    for item in release["trace"]:
        item["event_id"] = release["output_object_id"]
    context_records[1][-1]["parsed_content_b64"] = encoded(canonical(release))
    return context_records


def test_native_context_reader_accepts_attributed_source_semantics(native_context_records):
    assert inspect(native_context_records).verified


def test_native_context_reader_rejects_semantics_attributed_to_another_source(
    native_context_records,
):
    context = {
        "schema": "tn.llama.decision-context.v1",
        "sources": [{"object_id": "sha256:" + "f" * 64, "governance": {"policy": "other-source"}}],
    }
    bind_context(native_context_records, 1, context)
    assert not inspect(native_context_records).verified


def test_context_reader_rejects_empty_context_with_consistent_artifact_digests(context_records):
    bind_context(context_records, 1, {})
    assert not inspect(context_records).verified


def test_witness_keeps_retained_echo_evidence_explicit(reference_run):
    path = reference_run / "runtime/decision-events.ndjson"
    audit = [json.loads(line) for line in path.read_text().splitlines()]
    admission = audit[0]
    facts = json.loads(admission["facts_json"])
    facts.pop("governance_context_protocol")
    facts.update(governance_value_count=6, governance_commitment_count=6)
    admission["facts_json"] = json.dumps(facts)
    echo = {
        **admission,
        "kind": "commitments_matched",
        "facts_json": json.dumps({"hashes_matched": True, "governance_commitment_count": 6}),
    }
    audit = [admission, echo] + [
        row
        for row in audit
        if row["kind"]
        not in {
            "governance_opened_and_verified",
            "governance_context_bound",
            "turn_begin_authorized",
        }
    ]
    for index, row in enumerate(audit):
        row["sequence"] = index
    write_rows(path, audit)
    write_rows(reference_run / "runtime/raw-trace/run-context.sensitive.ndjson", [])
    result = verify_reference_run(reference_run)
    assert result.all_full
    assert result.governance_context.protocol == "legacy_echo"
    assert "commitments matched" in result.questions[2].evidence


def test_witness_requires_retained_context_execution_evidence(reference_run):
    write_rows(reference_run / "runtime/raw-trace/run-context.sensitive.ndjson", [])
    result = verify_reference_run(reference_run)
    assert not result.all_full
    assert result.questions[2].status == "not_shown"
    assert result.questions[5].status == "not_shown"


def test_context_reader_rejects_executed_action_with_deleted_turn_evidence(context_records):
    audit, trace = context_records
    executed = copy.deepcopy(audit[4])
    executed.update(kind="governed_tool_executed", sequence=len(audit))
    audit.append(executed)
    del audit[3:5]
    del trace[3:6]
    assert not inspect(context_records).verified


def test_context_reader_rejects_history_truncated_before_report_turn(context_records):
    audit, trace = context_records
    del audit[5:]
    del trace[6:]
    result = inspect(context_records)
    assert not result.verified
    assert "completion" in " ".join(result.errors)


@pytest.mark.parametrize("kind", ["output_emitted_and_read_back", "source_chain_committed"])
def test_context_reader_requires_report_emission_and_completion(context_records, kind):
    audit = context_records[0]
    audit[:] = [row for row in audit if row["kind"] != kind]
    assert not inspect(context_records).verified


def test_context_reader_requires_retained_release(context_records):
    context_records[1].pop()
    assert not inspect(context_records).verified


@pytest.mark.parametrize("field,value", [
    ("task_id", 41), ("slot_id", 1), ("run_id", "other-run"), ("phase", 3),
])
def test_context_reader_binds_release_to_report_inference(context_records, field, value):
    context_records[1][-1][field] = value
    assert not inspect(context_records).verified


def test_context_reader_rejects_completion_spliced_from_an_earlier_turn(context_records):
    audit = context_records[0]
    for row in audit[-2:]:
        row.update(llama_task_id=41, facts_json=audit[4]["facts_json"])
    assert not inspect(context_records).verified


def test_context_reader_rejects_release_reassigned_to_an_earlier_inference(context_records):
    audit, trace = context_records
    for row in audit[-2:]:
        row.update(llama_task_id=41, facts_json=audit[4]["facts_json"])
    del audit[5:7]
    del trace[6:9]
    trace[-1]["task_id"] = 41
    expected = json.loads(base64.b64decode(trace[-1]["parsed_content_b64"]))
    result = inspect(context_records, expected_release=expected)
    assert not result.verified
    assert "release" in " ".join(result.errors)


def test_context_reader_requires_exact_expected_release(context_records):
    expected = json.loads(base64.b64decode(context_records[1][-1]["parsed_content_b64"]))
    assert inspect(context_records, expected_release=expected).verified
    expected["output_row_hash"] = "sha256:" + "e" * 64
    assert not inspect(context_records, expected_release=expected).verified


@pytest.fixture
def runtime_context_records(native_context_records):
    audit, trace = native_context_records
    runtime_events = [
        {
            **audit[0],
            "kind": kind,
            "facts_json": json.dumps({
                "source_object_id": audit[0]["target_row_hash"],
                "content_digest": "sha256:" + "d" * 64,
            }),
        }
        for kind in (
            "sections_selected_runtime",
            "governed_tool_executed_runtime",
            "tool_result_accepted_runtime",
        )
    ]
    audit[1:5] = runtime_events
    del trace[:6]
    for sequence, row in enumerate(audit):
        row["sequence"] = sequence
    for sequence, row in enumerate(trace):
        row["sequence"] = sequence
    retain_release_actions(audit, trace)
    return audit, trace


def test_context_reader_accepts_one_report_inference_after_runtime_actions(runtime_context_records):
    result = inspect(runtime_context_records)
    assert result.verified, result.errors
    assert result.phases == (4,)
    assert result.task_ids == (42,)


def test_context_reader_accepts_runtime_tool_after_model_section_choice(native_context_records):
    audit, trace = native_context_records
    audit[3:5] = [
        {
            **audit[0],
            "kind": kind,
            "facts_json": json.dumps({"content_digest": "sha256:" + "d" * 64}),
        }
        for kind in ("governed_tool_executed_runtime", "tool_result_accepted_runtime")
    ]
    del trace[3:6]
    for sequence, row in enumerate(audit):
        row["sequence"] = sequence
    retain_release_actions(audit, trace)
    result = inspect(native_context_records)
    assert result.verified, result.errors
    assert result.phases == (3, 4)
    assert result.task_ids == (31, 42)


def test_context_reader_requires_selection_before_report_inference(runtime_context_records):
    runtime_context_records[0].pop(1)
    assert not inspect(runtime_context_records).verified


def test_context_reader_rejects_runtime_actions_with_model_identity(runtime_context_records):
    runtime_context_records[0][2]["llama_task_id"] = 42
    assert not inspect(runtime_context_records).verified


def test_context_reader_rejects_runtime_action_before_admission(runtime_context_records):
    audit = runtime_context_records[0]
    audit[0], audit[1] = audit[1], audit[0]
    for sequence, row in enumerate(audit):
        row["sequence"] = sequence
    assert not inspect(runtime_context_records).verified


def test_context_reader_requires_runtime_tool_result_acceptance(runtime_context_records):
    runtime_context_records[0].pop(3)
    assert not inspect(runtime_context_records).verified


def test_context_reader_rejects_deleted_runtime_execution_and_acceptance(runtime_context_records):
    audit, trace = runtime_context_records
    expected = json.loads(base64.b64decode(trace[-1]["parsed_content_b64"]))
    assert inspect(runtime_context_records, expected_release=expected).verified
    audit[:] = [row for row in audit if row["kind"] not in {
        "governed_tool_executed_runtime", "tool_result_accepted_runtime",
    }]
    assert not inspect(runtime_context_records, expected_release=expected).verified


def test_witness_rejects_whole_middle_inference_deleted_from_audit_and_trace(reference_run):
    audit_path = reference_run / "runtime/decision-events.ndjson"
    audit = [json.loads(line) for line in audit_path.read_text().splitlines()]
    audit = [row for row in audit if row.get("llama_task_id") != 41]
    write_rows(audit_path, audit)
    trace_path = reference_run / "runtime/raw-trace/run-context.sensitive.ndjson"
    trace = [json.loads(line) for line in trace_path.read_text().splitlines()]
    del trace[3:6]
    write_rows(trace_path, trace)
    result = verify_reference_run(reference_run)
    assert not result.all_full
    assert not result.governance_context.verified


def test_context_reader_rejects_release_receipt_without_matching_tool(runtime_context_records):
    audit, trace = runtime_context_records
    release = json.loads(base64.b64decode(trace[-1]["parsed_content_b64"]))
    receipt = next(item for item in release["trace"] if item["event"] == "receipt_inserted")
    receipt["row_hash"] = "sha256:" + "f" * 64
    trace[-1]["parsed_content_b64"] = encoded(canonical(release))
    assert not inspect((audit, trace), expected_release=release).verified


def test_context_reader_rejects_mismatched_retained_release_source(context_records):
    release = json.loads(base64.b64decode(context_records[1][-1]["parsed_content_b64"]))
    release["source_row_hash"] = "sha256:" + "e" * 64
    context_records[1][-1]["parsed_content_b64"] = encoded(canonical(release))
    assert not inspect(context_records).verified


def test_witness_binds_context_to_received_release(reference_run):
    path = reference_run / "runtime/raw-trace/run-context.sensitive.ndjson"
    trace = [json.loads(line) for line in path.read_text().splitlines()]
    release = json.loads(base64.b64decode(trace[-1]["parsed_content_b64"]))
    release["output_row_hash"] = "sha256:" + "e" * 64
    trace[-1]["parsed_content_b64"] = encoded(canonical(release))
    write_rows(path, trace)
    result = verify_reference_run(reference_run)
    assert not result.all_full
    assert result.governance_context.verified is False


def test_witness_accepts_runtime_selection_and_tools_before_report_inference(reference_run):
    path = reference_run / "runtime/decision-events.ndjson"
    audit = [json.loads(line) for line in path.read_text().splitlines()]
    runtime_events = [
        {
            **audit[0],
            "kind": kind,
            "facts_json": json.dumps({"content_digest": "sha256:" + "d" * 64}),
        }
        for kind in (
            "sections_selected_runtime",
            "governed_tool_executed_runtime",
            "tool_result_accepted_runtime",
        )
    ]
    audit = [audit[0], *runtime_events] + [
        row for row in audit[1:] if row.get("llama_task_id") not in {31, 41}
    ]
    for sequence, row in enumerate(audit):
        row["sequence"] = sequence
    write_rows(path, audit)
    path = reference_run / "runtime/raw-trace/run-context.sensitive.ndjson"
    trace = [json.loads(line) for line in path.read_text().splitlines()][6:]
    retain_release_actions(audit, trace)
    write_rows(path, trace)
    client_path = reference_run / "client/http.ndjson"
    client = [json.loads(line) for line in client_path.read_text().splitlines()]
    response = next(row for row in client if row.get("direction") == "response")
    response["body_b64"] = trace[-1]["parsed_content_b64"]
    write_rows(client_path, client)
    result = verify_reference_run(reference_run)
    assert result.all_full, [(item.number, item.status) for item in result.questions]
    assert result.governance_context.phases == (4,)


def test_witness_rejects_malformed_admission_with_an_echo_assertion(reference_run):
    path = reference_run / "runtime/decision-events.ndjson"
    audit = [json.loads(line) for line in path.read_text().splitlines()]
    audit[0]["facts_json"] = "{malformed"
    echo = {
        **audit[0],
        "kind": "commitments_matched",
        "facts_json": json.dumps({"hashes_matched": True, "governance_commitment_count": 6}),
    }
    audit = [row for row in audit if row["kind"] != "governance_context_bound"] + [echo]
    write_rows(path, audit)
    write_rows(reference_run / "runtime/raw-trace/run-context.sensitive.ndjson", [])
    result = verify_reference_run(reference_run)
    assert not result.all_full
    assert result.questions[2].status == result.questions[5].status == "not_shown"
