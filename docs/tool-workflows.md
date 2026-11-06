# Tool workflows

`ToolWorkflow` executes registered tools over governed artifacts. The caller supplies an `Endpoint`, a `ToolRegistry`, and named inputs. Each call passes schema validation, endpoint authorization, and required actions before its handler receives opened values. The result is published as a governed artifact with its contributing policies, claims, and input references.

## Register and execute a tool

The [runnable example](../examples/governed_tools.py) includes the session, policy file, endpoint evaluator, and tool setup. With `endpoint` and the governed `amount` configured:

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

`ToolInvocation` contains detached JSON arguments, opened input values, an invocation binding, and an idempotency key. The handler's ordinary JSON result is checked against `output_schema` before publication. `completion.artifact` retains the source governance; `completion.handle` names it as `result:scaled` for later calls.

## Dependencies and model integration

A `Call` contains an ID, registered tool name, arguments, input handles, and call dependencies. `Call.from_dict(...)` validates the closed call shape. Applications can translate a model's proposed tool calls into these records and submit them through `execute` or `execute_many`.

```python
workflow.execute_many((
    Call("second", "scale", {"factor": 2}, inputs=("result:first",), depends_on=("first",)),
    Call("first", "scale", {"factor": 3}, inputs=("amount",)),
))
```

`execute_many` validates the dependency graph and executes calls in dependency order. Each call retains the initial workflow inputs as control dependencies, together with its selected inputs and completed-call dependencies. `execute(call, control=...)` accepts additional governed control artifacts.

The application controls the model loop and transport. It can disclose a governed input or tool result with `workflow.expose(handle, destination=...)`; this calls the endpoint's disclosure gate. The [native LLM integration](../native/tn-llama) supplies governed input admission, field access, tool-action checks, and governed output publication within llama.cpp.

## Remote results

`ToolSpec(result_mode="governed", ...)` expects an `ArtifactBundle` from another endpoint and requires a `result_admit(publication, manifest)` callback. The callback receives the verified publication and manifest and must accept the producer and operation contract explicitly.

The remote producer binds `parameters={"tool_call": invocation.binding}` to its result. The receiving endpoint checks this binding, evaluates the returned policies, and validates the output schema. An optional `result_validator(invocation, value)` can check the calculation or a tool-specific receipt. Both callbacks must return exactly `True` to accept a result.

## Release and retries

`workflow.finish(value, schema=..., destination=...)` checks the output schema, completion of attempted calls, and the configured `required_tools`. The endpoint then authorizes `workflow.release`, completes required actions, and publishes the result with input and completion references. The returned artifact remains governed. Ordinary JSON is obtained through `endpoint.reveal(artifact, destination=...)`.

A repeated successful call with the same ID and contents returns its retained completion. Changed arguments, names, inputs, or dependencies under that ID are rejected. Failed actions block release. An explicit `execute(call, retry=True)` requires `ToolSpec(retryable=True, ...)` and retains the idempotency key; the handler applies that key to external side effects.

Each workflow serializes its calls. Separate endpoint instances can execute concurrently. `workflow.events` records started, completed, failed, and released states.
