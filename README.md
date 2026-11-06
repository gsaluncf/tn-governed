# TN Governed

TN Governed is a framework for applying data-use policies across LLM applications, tools, and data processing services. Governed values and artifacts retain their source policies, attributed claims, and derivation links through computation and transfer between endpoints.

Each endpoint has its own keys, recognized authorities, policy evaluator, and required-action handlers. It verifies incoming publications and authorizes the requested use before opening protected values. Derived results are encrypted and signed, with the source governance retained for the next recipient.

![Data, tool, and LLM endpoints exchange governed publications. Each endpoint applies its own authority rules.](assets/diagrams/framework.svg)

## LLMs and tools

The native llama.cpp integration verifies governed inputs, controls access to encrypted fields, checks required tool completions, and publishes governed model outputs. Applications configure the permitted uses and actions.

`ToolWorkflow` runs registered application tools over governed artifacts. A call names the tool, arguments, input handles, and dependencies. The endpoint checks the call before invoking its handler, validates the result, and retains the contributing policies and claims. Release requires every attempted call to succeed and the configured required tools to have completed.

The application supplies calls to `ToolWorkflow.execute` or `execute_many`. These calls can come from an application or be translated from a model's tool-call output. The [tool workflow guide](docs/tool-workflows.md) describes registration, dependencies, remote results, and release.

## Installation

Use Python 3.12, [uv](https://docs.astral.sh/uv/), Rust 1.95 or newer, and a C/C++ build toolchain. From the repository root:

```sh
uv sync --locked --extra dev
```

This builds the included native TN SDK and installs the local Polars adapter and model client. Windows builds require the Visual Studio C++ Build Tools. The tool example below runs locally with that environment.

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

The [example](examples/governed_tools.py) loads a [local policy](examples/tool_workflow.policy), creates a governed numeric value, attaches a claim, and executes a registered scaling tool. Its endpoint evaluator permits named operations and disclosure to `console`.

With the endpoint and governed input configured, tool registration and execution use:

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

`completion.artifact` is a governed result. `workflow.finish(...)` publishes the workflow output after checking its schema and release requirements. Ordinary values are obtained through an authorized `endpoint.reveal(...)` or `workflow.expose(...)` call to a named destination.

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

The [execution guide](docs/governed-execution.md) describes endpoint authorization, required actions, claim attribution, and transfers. [Interfaces and source layout](docs/interfaces.md) links these contracts to their implementations.

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

The research paper, *Governance That Travels: Governed Values Across SQL, Dataframes, and Language Models*, evaluates the SQL, dataframe, and LLM integrations.
