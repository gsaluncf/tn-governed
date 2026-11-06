# TN Governed

TN Governed is a framework for applying data-use policies across LLM applications, tools, and data processing services. It supports workflows that combine database queries, dataframe operations, calculations, tool calls, and model inference while retaining the conditions attached to the source data.

Data-use conditions can specify a permitted purpose, a disclosure destination, or an action required before processing. Calculations, tool results, and model outputs can depend on several sources with different conditions. The SQL, Polars, tool, and inference integrations retain those source conditions in derived publications. Each receiving runtime evaluates the requested use under its configured rules before opening protected values.

The framework represents protected content as governed values and artifacts. Each encrypted, signed TN publication contains the value and its governance, including source policies, attributed claims, and derivation links. Signed decisions and action records provide evidence of the processing performed. A receiving service can verify the source statements and evaluate the requested use under its own authority configuration.

![Data, tool, and LLM endpoints exchange governed publications. Each endpoint applies its own authority rules.](assets/diagrams/framework.svg)

## Core components

`Endpoint` provides the execution boundary for a service, tool, or recipient. Each instance has its own keys, recognized authorities, policy evaluator, and required-action handlers. Before protected computation, `Endpoint` verifies the inputs, obtains a policy decision, and completes required actions. Successful computation produces a governed artifact containing the result and source governance. Disclosure as an ordinary value requires authorization for a named destination.

`ToolWorkflow` executes registered tools over governed inputs. Tool registration specifies the handler and its input and output schemas. The workflow validates requests, executes dependent calls in order, and publishes a final result after the required calls and release actions have completed.

The native llama.cpp integration controls access to encrypted input fields, verifies required tool completions, and publishes governed model outputs. The native runtime performs these checks within the inference service using its configured policies and keys.

`GovernedSQL` and `GovernedLazyFrame` integrate SQL and Polars processing with the same publication format. Query results, transformations, and aggregates retain source policies, original claim attribution, and contributor information for subsequent processing and recipient verification.

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
