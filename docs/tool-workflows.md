`ToolWorkflow` runs registered tools over `Endpoint` artifacts. `ToolRunner` supplies a bounded model loop. A provider proposes calls; the endpoint authorizes their named operation, source policies, claims, arguments, destination, and required actions before the handler runs. The model does not grant authority by echoing governance values.

The transport format is the native TN publication. The runtime uses `Endpoint.execute`, `metadata`, `reveal`, and `export`/`receive`; it does not supply a separate cipher, signer, or policy resolver. Source artifacts enter through a run-local handle map. Plain values returned by `reveal` cannot enter that map as governed inputs.

| Transition | Runtime check | Evidence and result |
| --- | --- | --- |
| Register a tool | Unique provider-compatible name; valid JSON input/output schemas; configured handler, operation and result mode | Immutable schema configuration |
| Accept a proposed call | Closed call shape, ordinary JSON arguments, registered name, schema, known handles, acyclic dependencies, call-ID consistency | A call remains unexecuted if these checks fail |
| Invoke a tool | Endpoint verifies inputs and evaluates the operation and required actions before opening values or calling the handler | Signed Decision and Result, or Refusal/Failure |
| Accept a remote result | Native publication and tool-specific producer admission, exact signed invocation binding, local authorization of the returned policy union, output schema and optional result validator | Governed output retaining local inputs and remote source policies and claims |
| Present data to a model | Explicit endpoint `reveal` to the configured model destination | Signed Disclosure; otherwise the model receives only handles and publication identities |
| Request a model turn | Endpoint authorizes `model.turn` before the provider request | Signed turn publication plus metadata trace entries for request/response and proposed call IDs |
| Release a workflow result | Every attempted call succeeded, configured required tools completed, final JSON satisfies the result schema, endpoint permits `workflow.release` and completes its actions | Governed result with input, tool, turn, claim, and action-record references |

Tool handlers receive an immutable `ToolInvocation` with detached arguments and opened input values. Each call includes the workflow's initial inputs as control dependencies and the selected data and completed-call dependencies. Provider-driven calls also include the signed proposing turn. This conservative policy union keeps earlier sources attached when a model chooses a later action based on their data.

`ToolSpec.result_mode="local"` publishes schema-validated JSON returned by the configured handler. `result_mode="governed"` expects an `ArtifactBundle` from another endpoint and requires a `result_admit(publication, manifest)` callback. The callback receives the signature-verified native publication and its verified manifest, checks the configured producer and operation contract, and must return exactly `True`. The remote producer binds `parameters={"tool_call": invocation.binding}` to its result. The receiving endpoint checks both that binding and tool-specific admission before opening remote business content, evaluates the added policies, and publishes the merged result. A `result_validator(invocation, value)` may additionally validate a computation or a tool-specific receipt; it must return exactly `True`.

Each logical call has a run-scoped ID. Repeating a successful call with identical arguments returns its retained completion. Changing its name, arguments, inputs, or dependencies under the same ID is rejected. The provider loop never retries failed actions. An explicit `execute(call, retry=True)` requires `ToolSpec.retryable=True` and reuses `invocation.idempotency_key`; the handler is responsible for applying that key to external side effects. The key hashes the run, call, tool, arguments, selected inputs, complete governance input scope, dependency IDs, operation, result mode, and schemas. A different input or contract therefore yields a different key even if another workflow reuses the run and call IDs. A retry must preserve its original control inputs. Failed actions block release. A run serializes its invocations, while separate endpoint instances can make independent decisions concurrently.

`ChatCompletionsProvider` and `ResponsesProvider` normalize their respective function-call and result-message shapes. They retain call IDs, reject incomplete or refused outcomes, and exclude reasoning blocks and text accompanying tool calls from final output. The shapes follow the [function-calling interface](https://developers.openai.com/api/docs/guides/function-calling). `JsonHTTPTransport` sends a single bounded JSON HTTP request without redirects or automatic retries. A configured local or remote model can be used through either adapter. Provider credentials remain in transport configuration.

The model receives a list of source handles and the requested result schema. Registered tools determine whether their results may be presented as model-visible plaintext; that presentation still requires a separate endpoint disclosure decision. `model_inputs` explicitly selects initial inputs to disclose. Invalid terminal JSON permits one formatting retry by default with tools disabled. Turn and distinct-call limits stop unfinished workflows without releasing a result. The metadata trace records proposed, started, completed, and failed calls separately and contains no raw tool values or provider reasoning.

```python
from tn_governed.tool_providers import ChatCompletionsProvider, JsonHTTPTransport
from tn_governed.tool_runtime import ToolRegistry, ToolRunner, ToolSpec, ToolWorkflow

tools = ToolRegistry((ToolSpec(
    "calculate",
    input_schema={"type": "object", "properties": {"factor": {"type": "number"}},
                  "required": ["factor"], "additionalProperties": False},
    output_schema={"type": "number"},
    handler=lambda invocation: invocation.values[0] * invocation.arguments["factor"],
    model_visible=True,
),))
workflow = ToolWorkflow(endpoint, tools, {"amount": governed_amount},
                        required_tools=("calculate",))
provider = ChatCompletionsProvider(
    JsonHTTPTransport(model_url, headers=provider_headers),
    model=model_name, identity="configured-inference",
)
result = ToolRunner(provider).run(
    workflow, prompt,
    result_schema={"type": "object", "properties": {"answer": {"type": "number"}},
                   "required": ["answer"], "additionalProperties": False},
    destination="internal-review",
)
```

The caller supplies the endpoint's keys, recognized authorities, policy evaluator, action handlers, model transport, and governed input. The returned `result` remains a governed artifact. Its ordinary JSON value is obtained only through an independently authorized `endpoint.reveal(result, destination=...)`.
