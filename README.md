# TN Governed

TN Governed is a framework for applying data-use policies across LLM applications, tools, and data processing services. TN publications contain the computed values, source policies, attributed claims, and derivation links used for authorization at subsequent endpoints.

Each `Endpoint` instance has a configured session, keys, recognized authorities, policy evaluator, and required-action handlers. `Endpoint.execute()` verifies input publications and obtains authorization from the configured evaluator before opening protected values or executing the computation. On success, `Endpoint.execute()` returns an encrypted, signed artifact containing the result and source governance.

![Data, tool, and LLM endpoints exchange governed publications. Each endpoint applies its own authority rules.](assets/diagrams/framework.svg)

## LLMs and tools

The Rust `tn-runtime` integration in llama.cpp verifies input publications, authorizes access to encrypted fields, checks required tool completions, and publishes encrypted model outputs with their source governance. Runtime configuration specifies permitted uses and required actions.

Each `ToolSpec` defines a handler, an input schema, and an output schema. `ToolWorkflow.execute()` accepts a `Call` record containing a tool name, arguments, input handles, and dependency IDs. Before handler invocation, `ToolWorkflow.execute()` validates the arguments and invokes `Endpoint.execute()` for authorization and required-action execution. `ToolSpec.validate_output()` checks the handler result against the output schema before `Endpoint` publishes the governed result.

`ToolWorkflow.execute_many()` accepts a sequence of `Call` records and executes them in dependency order. `ToolWorkflow.finish()` publishes a workflow result only after every attempted call has succeeded, every required tool has completed, and `Endpoint.execute("workflow.release", ...)` has authorized publication and completed required actions. The [tool workflow guide](docs/tool-workflows.md) specifies these inputs, validation rules, and outputs.

## Installation

Build requirements are Python 3.12, [uv](https://docs.astral.sh/uv/), Rust 1.95 or newer, and a C/C++ toolchain. Environment creation from the repository root:

```sh
uv sync --locked --extra dev
```

`uv sync` builds the included native TN SDK through Maturin and installs the local Polars adapter and model client. Windows builds require the Visual Studio C++ Build Tools. `examples/governed_tools.py` requires this Python environment.

The SQL/Polars examples also use Unity Catalog and OPA. Native LLM inference uses the included server integration and compatible GGUF model weights. [Installation and native builds](docs/installation.md) covers these components and their configuration.

## Tool workflow example

```sh
uv run python examples/governed_tools.py
```

Output:

```text
{"scaled": 36}
Retained claims: 1
Verified signed records: 9
```

[governed_tools.py](examples/governed_tools.py) loads [tool_workflow.policy](examples/tool_workflow.policy), originates the value `12`, attaches a claim, and registers a scaling handler. The example's `evaluate(request)` callback checks the application, purpose, permitted operations, recognized writer, source contract, and disclosure destination. The registered tool multiplies the value by `3`; the final JSON output is `{"scaled": 36}`.

The following excerpt requires a configured `Endpoint` instance named `endpoint` and a `GovernedArtifact` named `amount`:

```python
from tn_governed.tool_runtime import Call, ToolRegistry, ToolSpec, ToolWorkflow

tools = ToolRegistry((ToolSpec(
    "scale",
    input_schema={
        "type": "object",
        "properties": {"factor": {"type": "number"}},
        "required": ["factor"],
        "additionalProperties": False,
    },
    output_schema={"type": "number"},
    handler=lambda invocation: invocation.values[0] * invocation.arguments["factor"],
),))
workflow = ToolWorkflow(endpoint, tools, {"amount": amount}, required_tools=("scale",))
completion = workflow.execute(
    Call("scaled", "scale", {"factor": 3}, inputs=("amount",))
)
```

`ToolWorkflow.execute()` returns a `ToolCompletion`; its `artifact` field contains the governed result. `ToolWorkflow.finish(value, schema=..., destination=...)` validates and publishes the final workflow artifact. `Endpoint.reveal(artifact, destination=...)` and `ToolWorkflow.expose(handle, destination=...)` return ordinary values after authorization for the named destination.

## Interfaces

| Interface | Use |
| --- | --- |
| `Endpoint` | Originate, transform, attest, disclose, export, and receive governed JSON artifacts. |
| `ToolWorkflow` | Execute registered tools, retain call dependencies, and gate workflow release. |
| Native LLM runtime | Admit governed inputs, authorize field access and tool actions, and release governed model outputs. |
| `TNString`, `TNNumeric`, `Context` | Apply string and numeric operations while retaining source governance. |
| `GovernedSQL` | Publish parameterized SQLite query results with source policies and value/control dependencies. |
| `GovernedLazyFrame` | Apply Polars expressions and plans, retaining policies, claims, and contributor information. |
| `AuthorityEvaluator`, `ValueHistory` | Configure local authority decisions and required actions; retain signed value revisions. |

[Governed execution](docs/governed-execution.md) specifies endpoint authorization, required actions, claim attribution, and artifact transfer. [Interfaces and source layout](docs/interfaces.md) lists the implementation modules.

## Documentation

| Guide | Contents |
| --- | --- |
| [Installation and native builds](docs/installation.md) | Python environment, model-server builds, Unity, OPA, and runtime configuration. |
| [Tool workflows](docs/tool-workflows.md) | Registered tools, dependent calls, remote results, and governed release. |
| [Governed execution](docs/governed-execution.md) | Endpoint authority, required actions, claims, and artifact transfer. |
| [SQL query results](docs/sql-query-results.md) | Queries, contributor mappings, signed results, and disclosure. |
| [Polars adapter](dependencies/tn-polars/README.md) | Governed expressions, lazy plans, and dataframe publications. |
| [Examples](docs/examples.md) | Scalar operations, SQL/Polars, calculations, and an LLM report application. |
| [Evaluation](docs/evaluation.md) | Workloads, timing boundaries, recipient checks, and fault experiments. |

Research paper: *Governance That Travels: Governed Values Across SQL, Dataframes, and Language Models*.
