"""Registered tools execute through endpoint decisions across provider turns."""


import pytest
from test_endpoints import endpoints as endpoints

from tn_governed.tool_runtime import Call, ToolRegistry, ToolSpec, WorkflowError

NUMBER = {"type": "number"}
ARGS = {
    "type": "object",
    "properties": {"factor": NUMBER},
    "required": ["factor"],
    "additionalProperties": False,
}


def registry(handler=lambda invocation: invocation.arguments["factor"]):
    return ToolRegistry((ToolSpec("scale", ARGS, NUMBER, handler),))


def test_registered_schema_is_detached_and_checked():
    schema = {"type": "object", "properties": {}, "additionalProperties": False}
    tools = ToolRegistry((ToolSpec("lookup", schema, NUMBER, lambda _: 2),))
    schema["type"] = "array"
    assert tools["lookup"].input_schema["type"] == "object"
    exported = tools["lookup"].input_schema
    exported["type"] = "string"
    assert tools["lookup"].input_schema["type"] == "object"
    with pytest.raises(ValueError, match="reference"):
        ToolSpec("network", {"$ref": "https://example.invalid/schema"}, NUMBER, lambda _: 1)
    with pytest.raises(ValueError, match="duplicate"):
        ToolRegistry((tools["lookup"], tools["lookup"]))


def test_call_arguments_are_detached_json():
    arguments = {"factor": 2}
    call = Call("a", "scale", arguments, ("source",))
    arguments["factor"] = 10
    assert call.arguments == {"factor": 2}


def workflow_fixture(endpoints, tools, *, required=()):
    from tn_governed.tool_runtime import ToolWorkflow

    peers, policies = endpoints
    endpoint = peers["source"]
    one = endpoint.attest(endpoint.originate(2, policies=(policies[0],)), "amount is estimated")
    two = endpoint.originate(3, policies=(policies[1],))
    workflow = ToolWorkflow(endpoint, tools, {"source": one, "other": two}, required_tools=required)
    return workflow, endpoint, (one, two)


def test_multistep_tools_keep_policy_union_claims_and_required_actions(endpoints):
    from tn_governed.values.runtime import Assessment, ObligationResult

    tools = ToolRegistry(
        (
            ToolSpec("multiply", ARGS, NUMBER, lambda inv: inv.values[0] * inv.arguments["factor"]),
            ToolSpec(
                "combine",
                {"type": "object", "maxProperties": 0},
                NUMBER,
                lambda inv: sum(inv.values),
            ),
        )
    )
    workflow, endpoint, inputs = workflow_fixture(
        endpoints, tools, required=("multiply", "combine")
    )
    completions = workflow.execute_many(
        (
            Call("sum", "combine", {}, ("result:mul", "other"), ("mul",)),
            Call("mul", "multiply", {"factor": 3}, ("source",)),
        )
    )
    assert [result.call_id for result in completions] == ["mul", "sum"]
    assert workflow.expose("result:sum", destination="internal") == 9
    endpoint.obligations["record"] = lambda _: ObligationResult(True, "ledger:workflow-17")
    endpoint.evaluator = lambda request: Assessment(
        True, "authorized", ("record",) if request.operation == "workflow.release" else ()
    )
    artifact = workflow.finish({"answer": 9}, schema={"type": "object"}, destination="internal")
    assert endpoint.reveal(artifact, destination="internal") == {"answer": 9}
    original = endpoint.claims(inputs[0])[0]
    assert endpoint.claims(artifact)[0] == original
    view = endpoint.session.governance(endpoint.store.read(artifact.reference.object_id))
    assert len(view.governance.policies) == 2
    decision = next(record for record in endpoint.records() if record.id == artifact.decision_id)
    assert decision.body["details"]["discharged"][0]["evidence"] == "ledger:workflow-17"
    assert artifact.decision_id in endpoint.metadata(artifact)["action_records"]


def test_denied_call_and_invalid_arguments_do_not_open_values_or_invoke_handler(
    endpoints, monkeypatch
):
    from tn_governed.values.runtime import Assessment
    from tn_governed.values.string import OperationDenied

    calls = []
    workflow, endpoint, _ = workflow_fixture(
        endpoints, registry(lambda inv: calls.append(inv) or 1)
    )
    endpoint.evaluator = lambda _: Assessment(False, "purpose not permitted")
    monkeypatch.setattr(endpoint, "_open", lambda *args: pytest.fail("business values were opened"))
    with pytest.raises(WorkflowError, match="schema"):
        workflow.execute(Call("bad", "scale", {"factor": "oops"}, ("source",)))
    with pytest.raises(OperationDenied):
        workflow.execute(Call("denied", "scale", {"factor": 2}, ("source",)))
    assert calls == []
    assert not any(event["kind"] == "tool_started" for event in workflow.events)
    assert endpoint.records()[-1].body["kind"] == "Refusal"


def test_duplicate_calls_are_idempotent_and_changed_requests_are_rejected(endpoints):
    from concurrent.futures import ThreadPoolExecutor

    count = []
    workflow, _, _ = workflow_fixture(
        endpoints, registry(lambda inv: count.append(inv.idempotency_key) or 4)
    )
    call = Call("invoice", "scale", {"factor": 2}, ("source",))
    with ThreadPoolExecutor(2) as workers:
        outputs = list(workers.map(workflow.execute, (call, call)))
    assert outputs[0] == outputs[1] and len(count) == 1
    with pytest.raises(WorkflowError, match="reused"):
        workflow.execute(Call("invoice", "scale", {"factor": 7}, ("source",)))
    with pytest.raises(WorkflowError, match="reused"):
        workflow.execute_many(
            (
                Call("another", "scale", {"factor": 1}, ("source",)),
                Call("invoice", "scale", {"factor": 7}, ("source",)),
            )
        )
    assert len(count) == 1


def test_dependency_cycles_are_rejected_before_any_handler(endpoints):
    count = []
    workflow, _, _ = workflow_fixture(endpoints, registry(lambda inv: count.append(inv) or 4))
    with pytest.raises(WorkflowError, match="cycle"):
        workflow.execute_many(
            (
                Call("a", "scale", {"factor": 2}, ("result:b",)),
                Call("b", "scale", {"factor": 2}, ("result:a",)),
            )
        )
    assert count == []


def test_invalid_tool_results_block_dependents_and_release(endpoints):
    workflow, endpoint, _ = workflow_fixture(endpoints, registry(lambda _: {"unexpected": 3}))
    before = len([record for record in endpoint.records() if record.body["kind"] == "Result"])
    with pytest.raises(WorkflowError, match="result"):
        workflow.execute(Call("a", "scale", {"factor": 2}, ("source",)))
    assert (
        len([record for record in endpoint.records() if record.body["kind"] == "Result"]) == before
    )
    with pytest.raises(WorkflowError, match="dependency"):
        workflow.execute(Call("b", "scale", {"factor": 2}, ("source",), ("a",)))
    with pytest.raises(WorkflowError, match="failed"):
        workflow.finish({}, schema={"type": "object"}, destination="internal")


def test_retry_is_explicit_and_reuses_the_handler_idempotency_key(endpoints):
    keys = []

    def handle(invocation):
        keys.append(invocation.idempotency_key)
        if len(keys) == 1:
            raise ConnectionError("handler transport failed")
        return 7

    tools = ToolRegistry((ToolSpec("scale", ARGS, NUMBER, handle, retryable=True),))
    workflow, _, _ = workflow_fixture(endpoints, tools)
    call = Call("recoverable", "scale", {"factor": 2}, ("source",))
    with pytest.raises(ConnectionError):
        workflow.execute(call)
    with pytest.raises(WorkflowError, match="repeated"):
        workflow.execute(call)
    result = workflow.execute(call, retry=True)
    assert keys[0] == keys[1] and result.attempt == 2
    assert workflow.expose(result.handle, destination="internal") == 7


def test_required_tool_and_failed_release_action_prevent_result(endpoints):
    from tn_governed.values.runtime import Assessment, ObligationResult
    from tn_governed.values.string import OperationDenied

    workflow, endpoint, _ = workflow_fixture(endpoints, registry(), required=("scale",))
    with pytest.raises(WorkflowError, match="required"):
        workflow.finish({}, schema={"type": "object"}, destination="internal")
    workflow.execute(Call("done", "scale", {"factor": 2}, ("source",)))
    endpoint.evaluator = lambda _: Assessment(True, "conditional", ("review",))
    endpoint.obligations["review"] = lambda _: ObligationResult(False, "unavailable")
    with pytest.raises(OperationDenied):
        workflow.finish({}, schema={"type": "object"}, destination="internal")
    assert not any(event["kind"] == "workflow_released" for event in workflow.events)


def test_remote_tool_result_is_admitted_and_bound_to_exact_invocation(endpoints):
    peers, policies = endpoints
    remote = peers["analyst"]
    extra = remote.attest(remote.originate(5, policies=(policies[2],)), "remote source context")

    def handle(invocation):
        received = tuple(
            remote.receive(peers["source"].export(artifact)) for artifact in invocation.artifacts
        )
        output = remote.execute(
            "external.calculate",
            (*received, extra),
            lambda values: sum(values),
            parameters={"tool_call": invocation.binding},
        )
        return remote.export(output)

    tools = ToolRegistry(
        (
            ToolSpec(
                "scale",
                ARGS,
                NUMBER,
                handle,
                result_mode="governed",
                result_admit=lambda publication, manifest: (
                    publication.writer == remote.session.did
                    and manifest["operation"] == "external.calculate"
                ),
            ),
        )
    )
    workflow, endpoint, _ = workflow_fixture(endpoints, tools)
    result = workflow.execute(Call("remote", "scale", {"factor": 2}, ("source",)))
    assert workflow.expose(result.handle, destination="internal") == 7
    assert len(endpoint.claims(result.artifact)) == 2
    view = endpoint.session.governance(endpoint.store.read(result.artifact.reference.object_id))
    assert len(view.governance.policies) == 3


def test_stale_remote_result_is_rejected_before_its_business_values_open(endpoints, monkeypatch):
    peers, policies = endpoints
    remote = peers["analyst"]
    stale = remote.originate(
        17, policies=(policies[0],), parameters={"tool_call": {"run_id": "other"}}
    )
    tools = ToolRegistry(
        (
            ToolSpec(
                "scale",
                ARGS,
                NUMBER,
                lambda _: remote.export(stale),
                result_mode="governed",
                result_admit=lambda publication, _: publication.writer == remote.session.did,
            ),
        )
    )
    workflow, endpoint, _ = workflow_fixture(endpoints, tools)
    opened = []
    original = endpoint._open

    def observe(artifact, request):
        opened.append(artifact.reference.object_id)
        return original(artifact, request)

    monkeypatch.setattr(endpoint, "_open", observe)
    with pytest.raises(WorkflowError, match="invocation"):
        workflow.execute(Call("remote", "scale", {"factor": 2}, ("source",)))
    assert stale.reference.object_id not in opened


def test_remote_result_policy_is_checked_before_opening_its_content(endpoints, monkeypatch):
    from tn_governed.values.runtime import Assessment
    from tn_governed.values.string import OperationDenied

    peers, policies = endpoints
    remote = peers["analyst"]
    returned = []

    def remote_call(invocation):
        value = remote.originate(
            5, policies=(policies[2],), parameters={"tool_call": invocation.binding}
        )
        returned.append(value.reference.object_id)
        return remote.export(value)

    workflow, endpoint, _ = workflow_fixture(
        endpoints,
        ToolRegistry(
            (
                ToolSpec(
                    "scale",
                    ARGS,
                    NUMBER,
                    remote_call,
                    result_mode="governed",
                    result_admit=lambda publication, _: publication.writer == remote.session.did,
                ),
            )
        ),
    )
    endpoint.evaluator = lambda request: Assessment(
        not any(policy.matches_contract(policies[2]) for policy in request.policies),
        "local authority",
    )
    opened, original = [], endpoint._open

    def opening(value, request):
        opened.append(value.reference.object_id)
        return original(value, request)

    monkeypatch.setattr(endpoint, "_open", opening)
    with pytest.raises(OperationDenied):
        workflow.execute(Call("external", "scale", {"factor": 2}, ("source",)))
    assert returned and returned[0] not in opened


def test_configured_result_validation_rejects_wrong_computation(endpoints):
    tools = ToolRegistry(
        (
            ToolSpec(
                "scale",
                ARGS,
                NUMBER,
                lambda _: 9,
                result_validator=lambda inv, value: (
                    value == inv.values[0] * inv.arguments["factor"]
                ),
            ),
        )
    )
    workflow, _, _ = workflow_fixture(endpoints, tools)
    with pytest.raises(WorkflowError, match="validation"):
        workflow.execute(Call("incorrect", "scale", {"factor": 3}, ("source",)))


def test_plain_values_cannot_enter_governed_workflow_inputs(endpoints):
    from tn_governed.tool_runtime import ToolWorkflow

    endpoint = endpoints[0]["source"]
    with pytest.raises(TypeError, match="governed"):
        ToolWorkflow(endpoint, registry(), {"source": 7})


def test_governed_tool_requires_result_authority_admission():
    with pytest.raises(ValueError, match="admission"):
        ToolSpec("remote", {}, {}, lambda _: None, result_mode="governed")


def test_other_trusted_writer_cannot_impersonate_a_tool_result(endpoints, monkeypatch):
    peers, policies = endpoints
    wrong_producer = peers["restricted"]
    returned, inspected, opened = [], [], []

    def remote_call(invocation):
        value = wrong_producer.originate(
            5,
            policies=(policies[2],),
            operation="external.calculate",
            parameters={"tool_call": invocation.binding},
        )
        returned.append(value.reference.object_id)
        return wrong_producer.export(value)

    def admit(publication, manifest):
        inspected.append((publication.writer, manifest["operation"]))
        return publication.writer == peers["analyst"].session.did

    workflow, endpoint, _ = workflow_fixture(
        endpoints,
        ToolRegistry(
            (
                ToolSpec(
                    "scale", ARGS, NUMBER, remote_call, result_mode="governed", result_admit=admit
                ),
            )
        ),
    )
    original = endpoint._open

    def opening(value, request):
        opened.append(value.reference.object_id)
        return original(value, request)

    monkeypatch.setattr(endpoint, "_open", opening)
    with pytest.raises(WorkflowError, match="authority"):
        workflow.execute(Call("external", "scale", {"factor": 2}, ("source",)))
    assert inspected == [(wrong_producer.session.did, "external.calculate")]
    assert returned[0] not in opened


def test_reused_run_id_with_different_control_inputs_has_distinct_idempotency_key(endpoints):
    from tn_governed.tool_runtime import ToolWorkflow

    peers, policies = endpoints
    endpoint = peers["source"]
    first = endpoint.originate(1, policies=(policies[0],))
    second = endpoint.originate(2, policies=(policies[0],))
    keys = []
    tools = ToolRegistry(
        (
            ToolSpec(
                "scale", ARGS, NUMBER, lambda inv: keys.append(inv.idempotency_key) or inv.values[0]
            ),
        )
    )
    for control in (first, second):
        workflow = ToolWorkflow(
            endpoint, tools, {"source": first, "control": control}, run_id="same-run"
        )
        workflow.execute(Call("same-call", "scale", {"factor": 1}, ("source",)))
    assert keys[0] != keys[1]
