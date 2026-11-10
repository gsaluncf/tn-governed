"""Retained native context binds each decision to its admitted source and task."""

import base64
import copy
import hashlib
import json

import pytest


def encoded(raw):
    return base64.b64encode(raw).decode()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def digest(domain, raw):
    return "sha256:" + hashlib.sha256(domain.encode() + b"\0" + raw).hexdigest()


def v1_shaped_records():
    """The decision, model, and release history without the native object fields."""
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


def inspect(records, **expected):
    from tn_governed.context_evidence import inspect_governance_context

    return inspect_governance_context(
        *records,
        run_id="run-context",
        request_digest="sha256:" + "b" * 64,
        source_id="sha256:" + "a" * 64,
        **{"source_envelope": SIGNED_ENVELOPE, **expected},
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
        ("source_object_id", "sha256:" + "e" * 64),
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


def test_context_reader_gives_an_echo_no_credit(context_records):
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
    assert result.protocol == "unrecognized"
    assert not result.verified
    assert result.errors == ("a commitment echo proves nothing",)


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


def bind_context(records, turn, context, *, control_fields=None, tools=None, exchange=()):
    """Retain matching digests for a controlled semantic input."""
    audit, trace = records
    start = trace[turn * 3 + 1]
    request = json.loads(base64.b64decode(start["request_json_b64"]))
    control = json.loads(request["messages"][0]["content"])
    control["applicable_source_governance"] = context
    control.update(control_fields or {})
    request["messages"][0]["content"] = canonical(control).decode()
    request["messages"].extend(exchange)
    if tools is not None:
        request["tools"] = tools
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


GOVERNANCE_HASH = "hmac-sha256:v1:" + "1" * 64
DATA_HASH = "hmac-sha256:v1:" + "2" * 64
HASH_KEYS = {"governance_hash": GOVERNANCE_HASH, "data_hashes": [DATA_HASH]}
SIGNED_ENVELOPE = {"tn.agents": {"field_hashes": {"policy": GOVERNANCE_HASH}},
                   "values": {"field_hashes": {"value": DATA_HASH}}}


def decrypt_exchange(arguments=None):
    """The assistant call and tool result that every later native request retains."""
    call = {"id": "call-decrypt", "type": "function", "function": {
        "name": "decrypt_value", "arguments": json.dumps(arguments or HASH_KEYS),
    }}
    result = {"data": {"values": {"value": "ACME"}}, "governance_hash": GOVERNANCE_HASH}
    return [{"role": "assistant", "tool_calls": [call]},
            {"role": "tool", "tool_call_id": "call-decrypt", "content": json.dumps(result)}]


def generated_call(arguments, name="decrypt_value"):
    """The model's raw output in the backend's tool-call markup."""
    call = json.dumps({"name": name, "arguments": arguments})
    return f"<tool_call>\n{call}\n</tool_call>".encode()


@pytest.fixture
def context_records():
    """A native run's complete history: object identities, decrypt turns, and a v2 release."""
    return native_records(v1_shaped_records())


@pytest.fixture
def native_context_records(context_records):
    return context_records


def native_records(context_records):
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
    bind_context(
        context_records, 0, context,
        control_fields={"user_request": "Write the report.", "output_instruction": "Decrypt.",
                        "governance_hash": GOVERNANCE_HASH,
                        "encrypted_data": [{"group": "values", "field": "value",
                                            "data_hash": DATA_HASH}]},
        tools=[{"type": "function", "function": {"name": "decrypt_value"}}],
    )
    context_records[1][2]["raw_model_output_b64"] = encoded(generated_call(HASH_KEYS))
    for turn in (1, 2):
        bind_context(context_records, turn, context, exchange=decrypt_exchange())
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


@pytest.mark.parametrize("kind", ["output_emitted_and_read_back", "standalone_use_completed"])
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


@pytest.mark.parametrize(("change", "verified"), [
    ({}, True),
    ({"governance_hash": DATA_HASH}, False),
    ({"governance_hash": "hmac-sha256:v1:" + "3" * 64}, False),
    ({"data_hashes": [GOVERNANCE_HASH]}, False),
    ({"data_hashes": []}, False),
])
def test_context_reader_checks_the_presented_hash_keys(native_context_records, change, verified):
    arguments = {**HASH_KEYS, **change}
    context = json.loads(json.loads(base64.b64decode(
        native_context_records[1][4]["request_json_b64"]))["messages"][0]["content"])
    for turn in (1, 2):
        replace_exchange(native_context_records, turn, context, decrypt_exchange(arguments))
    assert inspect(native_context_records).verified is verified


def replace_exchange(records, turn, control, exchange):
    trace = records[1]
    for row in trace[turn * 3 : turn * 3 + 2]:
        request = json.loads(base64.b64decode(row["request_json_b64"]))
        request["messages"] = request["messages"][:1]
        row["request_json_b64"] = encoded(canonical(request))
    bind_context(records, turn, control["applicable_source_governance"], exchange=exchange)


@pytest.mark.parametrize(("policy", "verified"), [(GOVERNANCE_HASH, True), (DATA_HASH, False)])
def test_context_reader_compares_hash_keys_with_the_signed_object(
    native_context_records, policy, verified,
):
    envelope = {"tn.agents": {"field_hashes": {"policy": policy}},
                "values": {"field_hashes": {"value": DATA_HASH}}}
    assert inspect(native_context_records, source_envelope=envelope).verified is verified


@pytest.mark.parametrize("expected, verified", [
    (GOVERNANCE_HASH, True),
    (None, False),
    ("hmac-sha256:v1:" + "3" * 64, False),
])
def test_a_bound_objects_key_must_equal_the_readers_derivation(
    native_context_records, expected, verified,
):
    # A bound label carries `binding`; its key names governance the observer derives itself.
    labels = {"tn.agents": {"binding": 2}, "values": {"binding": 2}}
    envelope = {"tn.agents": {"field_hashes": {"policy": "unused for a bound object"}},
                "values": {"field_hashes": {"value": DATA_HASH}},
                "tn_aad": json.dumps(labels)}
    result = inspect(native_context_records, source_envelope=envelope, governance_hash_key=expected)
    assert result.verified is verified


def test_context_reader_rejects_native_values_without_a_model_decrypt_turn(native_context_records):
    audit, trace = native_context_records
    audit[:] = [row for row in audit if row.get("llama_task_id") != 31]
    del trace[:3]
    for sequence, row in enumerate(audit):
        row["sequence"] = sequence
    for sequence, row in enumerate(trace):
        row["sequence"] = sequence
    assert not inspect(native_context_records).verified


def test_context_reader_rejects_a_decrypt_turn_that_offers_another_tool(native_context_records):
    context = json.loads(json.loads(base64.b64decode(
        native_context_records[1][1]["request_json_b64"]))["messages"][0]["content"])
    bind_context(native_context_records, 0, context["applicable_source_governance"],
                 tools=[{"type": "function", "function": {"name": "emit_governed_record"}}])
    assert not inspect(native_context_records).verified


def test_context_reader_rejects_hash_keys_the_model_did_not_generate(native_context_records):
    native_context_records[1][2]["raw_model_output_b64"] = encoded(b"other tool response")
    assert not inspect(native_context_records).verified


def test_context_reader_rejects_a_result_beyond_the_presented_fields(native_context_records):
    context = json.loads(json.loads(base64.b64decode(
        native_context_records[1][4]["request_json_b64"]))["messages"][0]["content"])
    exchange = decrypt_exchange()
    exchange[1]["content"] = json.dumps({"governance_hash": GOVERNANCE_HASH,
                                         "data": {"values": {"value": "ACME", "other": "AC"}}})
    for turn in (1, 2):
        replace_exchange(native_context_records, turn, context, exchange)
    assert not inspect(native_context_records).verified


def test_context_reader_rejects_prose_holding_every_hash_key(native_context_records):
    prose = f"I would call decrypt_value with {GOVERNANCE_HASH} and {DATA_HASH}."
    native_context_records[1][2]["raw_model_output_b64"] = encoded(prose.encode())
    assert not inspect(native_context_records).verified


@pytest.mark.parametrize("raw", [
    generated_call({**HASH_KEYS, "note": DATA_HASH}),
    generated_call({"governance_hash": GOVERNANCE_HASH, "data_hashes": [DATA_HASH, DATA_HASH]}),
    generated_call(HASH_KEYS) + b" and prose",
    generated_call(HASH_KEYS) + generated_call(HASH_KEYS),
    generated_call(HASH_KEYS, name="emit_governed_record"),
])
def test_context_reader_requires_the_generated_call_to_be_the_retained_one(native_context_records, raw):
    native_context_records[1][2]["raw_model_output_b64"] = encoded(raw)
    assert not inspect(native_context_records).verified


def test_context_reader_accepts_reasoning_before_the_one_generated_call(native_context_records):
    raw = b"<think>\n\n</think>\n\n" + generated_call(HASH_KEYS)
    native_context_records[1][2]["raw_model_output_b64"] = encoded(raw)
    assert inspect(native_context_records).verified


def test_context_reader_rejects_hash_keys_without_a_decrypt_call(native_context_records):
    native_context_records[1][2]["raw_model_output_b64"] = encoded(json.dumps(HASH_KEYS).encode())
    assert not inspect(native_context_records).verified


def test_context_reader_requires_the_signed_object_for_native_evidence(native_context_records):
    assert not inspect(native_context_records, source_envelope=None).verified


@pytest.mark.parametrize("field", ["plaintext", "selected_values"])
def test_context_reader_rejects_values_beside_the_hash_keys(native_context_records, field):
    context = json.loads(json.loads(base64.b64decode(
        native_context_records[1][1]["request_json_b64"]))["messages"][0]["content"])
    bind_context(native_context_records, 0, context["applicable_source_governance"],
                 control_fields={field: "ACME: 12029"})
    assert not inspect(native_context_records).verified


def test_context_reader_rejects_a_value_already_in_the_decrypt_prompt(native_context_records):
    value = "ACME: 12029 demonstration cents"
    context = json.loads(json.loads(base64.b64decode(
        native_context_records[1][1]["request_json_b64"]))["messages"][0]["content"])
    bind_context(native_context_records, 0, context["applicable_source_governance"],
                 control_fields={"user_request": value})
    answer = {"data": {"values": {"value": value}}, "governance_hash": GOVERNANCE_HASH}
    exchange = decrypt_exchange()
    exchange[1]["content"] = json.dumps(answer)
    for turn in (1, 2):
        replace_exchange(native_context_records, turn, context, exchange)
    assert not inspect(native_context_records).verified


def runtime_tool_events(audit, count=2):
    kinds = ("governed_tool_executed_runtime", "tool_result_accepted_runtime")
    return [{**audit[0], "kind": kind, "facts_json": json.dumps({"content_digest": "sha256:" + "d" * 64})}
            for kind in kinds[:count]]


@pytest.fixture
def runtime_context_records(native_context_records):
    """The native shape: the model's decrypt turn, runtime tool actions, then the report turn."""
    audit, trace = native_context_records
    audit[3:5] = runtime_tool_events(audit)
    del trace[3:6]
    for sequence, row in enumerate(audit):
        row["sequence"] = sequence
    retain_release_actions(audit, trace)
    return audit, trace


def test_context_reader_accepts_runtime_tools_after_the_model_decrypt_turn(runtime_context_records):
    result = inspect(runtime_context_records)
    assert result.verified, result.errors
    assert result.phases == (3, 4)
    assert result.task_ids == (31, 42)


def test_context_reader_refuses_a_runtime_section_selection(native_context_records):
    audit, trace = native_context_records
    audit[1:5] = [{**audit[0], "kind": "sections_selected_runtime", "facts_json": "{}"},
                  *runtime_tool_events(audit)]
    del trace[:6]
    for sequence, row in enumerate(audit):
        row["sequence"] = sequence
    for sequence, row in enumerate(trace):
        row["sequence"] = sequence
    retain_release_actions(audit, trace)
    result = inspect(native_context_records)
    assert not result.verified
    assert "decrypt call" in " ".join(result.errors)


def test_context_reader_requires_the_model_decrypt_turn_before_runtime_actions(runtime_context_records):
    audit, trace = runtime_context_records
    del audit[1:3]
    del trace[:3]
    for sequence, row in enumerate(audit):
        row["sequence"] = sequence
    for sequence, row in enumerate(trace):
        row["sequence"] = sequence
    assert not inspect(runtime_context_records).verified


def test_context_reader_rejects_runtime_actions_with_model_identity(runtime_context_records):
    runtime_context_records[0][3]["llama_task_id"] = 42
    assert not inspect(runtime_context_records).verified


def test_context_reader_rejects_runtime_action_before_admission(runtime_context_records):
    audit = runtime_context_records[0]
    audit[0], audit[3] = audit[3], audit[0]
    for sequence, row in enumerate(audit):
        row["sequence"] = sequence
    assert not inspect(runtime_context_records).verified


def test_context_reader_requires_runtime_tool_result_acceptance(runtime_context_records):
    runtime_context_records[0].pop(4)
    assert not inspect(runtime_context_records).verified


def test_context_reader_rejects_deleted_runtime_execution_and_acceptance(runtime_context_records):
    audit, trace = runtime_context_records
    expected = json.loads(base64.b64decode(trace[-1]["parsed_content_b64"]))
    assert inspect(runtime_context_records, expected_release=expected).verified
    audit[:] = [row for row in audit if row["kind"] not in {
        "governed_tool_executed_runtime", "tool_result_accepted_runtime",
    }]
    assert not inspect(runtime_context_records, expected_release=expected).verified


def test_context_reader_rejects_release_receipt_without_matching_tool(runtime_context_records):
    audit, trace = runtime_context_records
    release = json.loads(base64.b64decode(trace[-1]["parsed_content_b64"]))
    receipt = next(item for item in release["trace"] if item["event"] == "receipt_inserted")
    receipt["row_hash"] = "sha256:" + "f" * 64
    trace[-1]["parsed_content_b64"] = encoded(canonical(release))
    assert not inspect((audit, trace), expected_release=release).verified


def test_context_reader_rejects_mismatched_retained_release_source(context_records):
    release = json.loads(base64.b64decode(context_records[1][-1]["parsed_content_b64"]))
    release["source_object_id"] = "sha256:" + "e" * 64
    context_records[1][-1]["parsed_content_b64"] = encoded(canonical(release))
    assert not inspect(context_records).verified


