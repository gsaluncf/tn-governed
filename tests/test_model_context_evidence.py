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
    return audit, trace


def write_rows(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


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
        42: "output_emitted_and_read_back",
    }
    with_actions = []
    for row in audit:
        with_actions.append(row)
        if row["kind"] == "turn_begin_authorized":
            with_actions.append({**row, "kind": actions[row["llama_task_id"]]})
    audit = with_actions
    audit.append({**audit[-1], "kind": "source_chain_committed"})
    audit.append(
        {
            "kind": "row_verified",
            "outcome": "allow",
            "facts_json": json.dumps({"signature_verified": True}),
        }
    )
    for sequence, row in enumerate(audit):
        row["sequence"] = sequence
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
        "run_id": "run-context",
        "source_event_id": "source-event",
        "source_row_hash": source_hash,
        "output_event_id": "output-event",
        "output_row_hash": output_hash,
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


def inspect(records):
    from tn_governed.context_evidence import inspect_governance_context

    return inspect_governance_context(
        *records,
        run_id="run-context",
        request_digest="sha256:" + "b" * 64,
        source_id="sha256:" + "a" * 64,
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
    for row in audit[turn * 2 + 1 : turn * 2 + 3]:
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
