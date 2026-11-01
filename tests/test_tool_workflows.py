"""Registered tools execute through endpoint decisions across provider turns."""

import json

import pytest
from test_endpoints import endpoints as endpoints

from tn_governed.tool_providers import ChatCompletionsProvider, ResponsesProvider
from tn_governed.tool_runtime import Call, ProviderTurn, ToolRegistry, ToolSpec, WorkflowError

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


def test_chat_provider_separates_tool_turns_and_matches_call_results():
    submitted = []
    responses = iter(
        [
            {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": "not a final answer",
                            "tool_calls": [
                                {
                                    "id": "scale-1",
                                    "type": "function",
                                    "function": {
                                        "name": "scale",
                                        "arguments": json.dumps(
                                            {
                                                "arguments": {"factor": 3},
                                                "inputs": ["source"],
                                                "depends_on": [],
                                            }
                                        ),
                                    },
                                },
                            ],
                        },
                        "finish_reason": "tool_calls",
                    }
                ]
            },
            {
                "choices": [
                    {
                        "message": {"role": "assistant", "content": '{"answer":6}'},
                        "finish_reason": "stop",
                    }
                ]
            },
        ]
    )
    provider = ChatCompletionsProvider(
        lambda body: submitted.append(body) or next(responses),
        model="local-model",
        identity="local-inference",
    )
    events = [{"kind": "user", "text": "calculate"}]
    first = provider.turn(events, registry().descriptions())
    assert first.text is None and first.calls == (
        Call("scale-1", "scale", {"factor": 3}, ("source",)),
    )
    events.extend(
        [
            {"kind": "assistant", "turn": first.to_dict()},
            {
                "kind": "tool",
                "call_id": "scale-1",
                "name": "scale",
                "result": {"handle": "result:scale-1"},
            },
        ]
    )
    assert provider.turn(events, registry().descriptions()).text == '{"answer":6}'
    assert submitted[1]["messages"][-1]["role"] == "tool"
    assert submitted[1]["messages"][-1]["tool_call_id"] == "scale-1"
    assert "not a final answer" not in repr(submitted[1])


def test_responses_provider_preserves_function_call_ids_without_reasoning():
    requests = []
    provider = ResponsesProvider(
        lambda body: (
            requests.append(body)
            or {
                "output": [
                    {"type": "reasoning", "summary": [{"text": "private reasoning"}]},
                    {
                        "type": "function_call",
                        "call_id": "calculation-17",
                        "name": "scale",
                        "arguments": (
                            '{"arguments":{"factor":2},"inputs":["source"],"depends_on":[]}'
                        ),
                    },
                ]
            }
        ),
        model="local",
        identity="responses-endpoint",
    )
    turn = provider.turn([{"kind": "user", "text": "compute"}], registry().descriptions())
    assert turn.calls[0].id == "calculation-17" and turn.text is None
    events = [
        {"kind": "assistant", "turn": turn.to_dict()},
        {
            "kind": "tool",
            "call_id": "calculation-17",
            "name": "scale",
            "result": {"handle": "result:calculation-17"},
        },
    ]
    provider.turn(events, registry().descriptions())
    assert requests[-1]["input"][1]["type"] == "function_call_output"
    assert requests[-1]["input"][1]["call_id"] == "calculation-17"
    assert "private reasoning" not in repr(requests)


@pytest.mark.parametrize(
    "arguments",
    [
        '{"arguments":{"factor":1,"factor":2},"inputs":["source"]}',
        '{"arguments":{"factor":2},"inputs":["source"],"extra":1}',
        '{"arguments":{"factor":2},"inputs":"source"}',
    ],
)
def test_provider_rejects_ambiguous_or_open_call_shapes(arguments):
    provider = ChatCompletionsProvider(
        lambda _: {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {
                                "id": "call",
                                "type": "function",
                                "function": {"name": "scale", "arguments": arguments},
                            },
                        ]
                    },
                    "finish_reason": "tool_calls",
                }
            ]
        },
        model="local",
        identity="local",
    )
    with pytest.raises(WorkflowError):
        provider.turn([], registry().descriptions())


def test_provider_turn_is_immutable_json_and_has_one_outcome():
    with pytest.raises(ValueError):
        ProviderTurn((Call("a", "scale", {"factor": 2}, ("source",)),), "answer")
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


def test_provider_loop_executes_multiple_tools_and_releases_a_governed_result(endpoints):
    from tn_governed.tool_runtime import ToolRunner

    calls = []
    tool = ToolSpec(
        "scale",
        ARGS,
        NUMBER,
        lambda inv: calls.append(inv.call_id) or inv.values[0] * inv.arguments["factor"],
        model_visible=True,
    )
    workflow, endpoint, _ = workflow_fixture(endpoints, ToolRegistry((tool,)), required=("scale",))

    class Provider:
        identity = "local"

        def turn(self, history, tools):
            results = [event for event in history if event["kind"] == "tool"]
            if not results:
                return ProviderTurn((Call("first", "scale", {"factor": 3}, ("source",)),))
            if len(results) == 1:
                assert results[0]["result"]["value"] == 6
                return ProviderTurn((Call("second", "scale", {"factor": 2}, ("result:first",)),))
            return ProviderTurn(text=json.dumps({"answer": results[-1]["result"]["value"]}))

    result = ToolRunner(Provider()).run(
        workflow, "calculate", result_schema={"type": "object"}, destination="internal"
    )
    assert endpoint.reveal(result, destination="internal") == {"answer": 12}
    assert calls == ["first", "second"]
    assert sum(event["kind"] == "provider_request" for event in workflow.events) == 3
    assert sum(event["kind"] == "tool_started" for event in workflow.events) == 2
    assert any(record.body["operation"] == "model.turn" for record in endpoint.records())
    assert endpoint.metadata(result)["operation"] == "workflow.release"


def test_model_call_is_authorized_before_provider_receives_any_request(endpoints):
    from tn_governed.tool_runtime import ToolRunner
    from tn_governed.values.runtime import Assessment
    from tn_governed.values.string import OperationDenied

    workflow, endpoint, _ = workflow_fixture(endpoints, registry())
    endpoint.evaluator = lambda request: Assessment(
        request.operation != "model.turn", "local authority"
    )

    class Provider:
        identity = "local"

        def turn(self, *args):
            pytest.fail("provider must not be called")

    with pytest.raises(OperationDenied):
        ToolRunner(Provider()).run(workflow, "calculate", result_schema={}, destination="internal")
    assert not any(event["kind"] == "provider_request" for event in workflow.events)


def test_format_retry_disables_tools(endpoints):
    from tn_governed.tool_runtime import ToolRunner

    workflow, endpoint, _ = workflow_fixture(endpoints, registry())
    seen = []

    class Provider:
        identity = "local"

        def turn(self, history, tools):
            seen.append(tools)
            return ProviderTurn(text="bad JSON" if len(seen) == 1 else '{"status":"ok"}')

    result = ToolRunner(Provider()).run(
        workflow, "format", result_schema={"type": "object"}, destination="internal"
    )
    assert seen[0] and not seen[1]
    assert endpoint.reveal(result, destination="internal") == {"status": "ok"}


def test_turn_budget_stops_a_provider_without_releasing_a_result(endpoints):
    from tn_governed.tool_runtime import ToolRunner

    workflow, _, _ = workflow_fixture(endpoints, registry())

    class Provider:
        identity = "local"

        def turn(self, history, tools):
            index = len([item for item in history if item["kind"] == "assistant"])
            return ProviderTurn((Call(f"step-{index}", "scale", {"factor": 2}, ("source",)),))

    with pytest.raises(WorkflowError, match="turn limit"):
        ToolRunner(Provider(), max_turns=2).run(
            workflow, "continue", result_schema={}, destination="internal"
        )
    assert sum(event["kind"] == "tool_started" for event in workflow.events) == 2
    assert not any(event["kind"] == "workflow_released" for event in workflow.events)


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


def test_http_transport_preserves_provider_request_and_limits_responses():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    from tn_governed.tool_providers import JsonHTTPTransport

    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            requests.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            body = json.dumps(
                {"choices": [{"message": {"content": '{"status":"ok"}'}, "finish_reason": "stop"}]}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/v1/chat/completions"
            provider = ChatCompletionsProvider(
                JsonHTTPTransport(url), model="local", identity="local"
            )
            assert provider.turn([{"kind": "user", "text": "hello"}], []).text == '{"status":"ok"}'
            assert requests[0]["messages"] == [{"role": "user", "content": "hello"}]
            with pytest.raises(WorkflowError, match="byte limit"):
                JsonHTTPTransport(url, max_response_bytes=4)({"model": "local"})
        finally:
            server.shutdown()
            thread.join(timeout=5)


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
