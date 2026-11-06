# Tool workflows

`ToolWorkflow(endpoint, tools, inputs, ...)` requires a configured `Endpoint`, a `ToolRegistry`, and a mapping from input handles to `GovernedArtifact` instances. `ToolWorkflow.execute(call)` validates the tool name, arguments, handles, and dependencies before invoking `Endpoint.execute()`. `Endpoint.execute()` obtains authorization, executes required actions, and opens the inputs before invoking the registered handler. The output is a signed governed artifact containing the handler result, source policies, claims, and input references.

## Register and execute a tool

[governed_tools.py](../examples/governed_tools.py) defines the session, policy file, evaluator, and tool registration. The following excerpt requires a configured `Endpoint` named `endpoint` and a `GovernedArtifact` named `amount`:

```python
from tn_governed.tool_runtime import Call, ToolRegistry, ToolSpec, ToolWorkflow

tools = ToolRegistry((ToolSpec(
    "scale",
    input_schema={"type": "object", "properties": {"factor": {"type": "number"}},
                  "required": ["factor"], "additionalProperties": False},
    output_schema={"type": "number"},
    handler=lambda invocation: invocation.values[0] * invocation.arguments["factor"],
),))
workflow = ToolWorkflow(endpoint, tools, {"amount": amount}, required_tools=("scale",))
completion = workflow.execute(Call("scaled", "scale", {"factor": 3}, inputs=("amount",)))
```

`ToolInvocation` contains detached JSON arguments, opened input values, an invocation binding, and an idempotency key. `ToolSpec.validate_output()` validates the handler's ordinary JSON result against `output_schema` before publication. `ToolCompletion.artifact` contains the governed result, and `ToolCompletion.handle` contains `result:scaled` for use in subsequent input lists.

## Dependencies and model integration

The `Call` fields are `id`, `name`, `arguments`, `inputs`, and `depends_on`. `Call.from_dict(...)` requires exactly these fields. `ToolWorkflow.execute()` and `execute_many()` require `Call` instances; model-generated requests must conform to this structure before submission.

```python
workflow.execute_many((
    Call("second", "scale", {"factor": 2}, inputs=("result:first",), depends_on=("first",)),
    Call("first", "scale", {"factor": 3}, inputs=("amount",)),
))
```

`ToolWorkflow.execute_many()` validates the dependency graph and executes calls in dependency order. `ToolWorkflow` includes the initial workflow inputs, selected data inputs, and completed-call results in the governed dependencies of each output. `ToolWorkflow.execute(call, control=...)` accepts additional governed control artifacts.

`ToolWorkflow.expose(handle, destination=...)` delegates disclosure to `Endpoint.reveal()`, which requires authorization for the named destination before returning an ordinary value. The Rust `tn-runtime` integration in [native/tn-llama](../native/tn-llama) implements publication admission, field access, required-tool checks, and governed output publication within llama.cpp.

## Remote results

For `ToolSpec(result_mode="governed", ...)`, the registered handler must return an `ArtifactBundle`. The registration must also include `result_admit(publication, manifest)`. `ToolWorkflow` invokes this callback with the verified publication and manifest; acceptance requires the return value `True`.

The remote `Endpoint.execute()` result must include `parameters={"tool_call": invocation.binding}`. `ToolWorkflow` admits the returned bundle through `Endpoint.receive()`, compares this signed binding with the original invocation, and invokes `result_admit`. `Endpoint.execute("tool.result", ...)` then authorizes the combined local and remote dependencies. `ToolSpec.validate_output()` validates the result schema and invokes the optional `result_validator(invocation, value)` callback. Callback acceptance requires exactly `True`.

## Release and retries

`ToolWorkflow.finish(value, schema=..., destination=...)` validates the final output schema and requires every attempted call to have succeeded and every configured `required_tools` entry to have completed. `ToolWorkflow.finish()` invokes `Endpoint.execute("workflow.release", ...)` for authorization, required actions, and publication. The returned `GovernedArtifact` contains input and tool-completion references. `Endpoint.reveal(artifact, destination=...)` returns ordinary JSON after destination-specific authorization.

For a repeated call with an identical ID and contents, `ToolWorkflow.execute()` returns the retained successful completion. Reuse of an ID with changed arguments, name, inputs, or dependencies raises `WorkflowError`. An attempted call with failed or incomplete status prevents `ToolWorkflow.finish()` from publishing a result. `ToolWorkflow.execute(call, retry=True)` requires `ToolSpec(retryable=True, ...)` and preserves `ToolInvocation.idempotency_key`. The registered handler is responsible for applying this key to external side effects.

`ToolWorkflow` serializes calls within a workflow. Separate `Endpoint` instances can execute concurrently. The `ToolWorkflow.events` property contains started, completed, failed, and released event records.
