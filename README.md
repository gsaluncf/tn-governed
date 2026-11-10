# TN Governed

TN Governed is a framework for applying data-use policies across LLM applications, tools, and data processing services. It supports workflows that combine database queries, dataframe operations, calculations, tool calls, and model inference while retaining the conditions attached to the source data.

Data-use conditions can specify a permitted purpose, a disclosure destination, or an action required before processing. Calculations, tool results, and model outputs can depend on several sources with different conditions. The SQL, Polars, tool, and inference integrations retain those source conditions in derived publications. Each receiving runtime evaluates the requested use under its configured rules before opening protected values.

The framework represents protected content as governed values and artifacts. Each encrypted, signed TN publication contains the value and its governance, including source policies, attributed claims, and derivation links. Signed decisions and action records provide evidence of the processing performed. A receiving service can verify the authorship and integrity of source statements and evaluate the requested use under its own authority configuration.

![Data, tool, and LLM endpoints exchange governed publications. Each endpoint applies its own authority rules.](assets/diagrams/framework.svg)

## Core components

`Endpoint` provides the execution boundary for a service, tool, or recipient. Each instance has its own keys, recognized authorities, policy evaluator, and required-action handlers. Before protected computation, `Endpoint` verifies the inputs, obtains a policy decision, and completes required actions. Successful computation produces a governed artifact containing the result and source governance. Disclosure as an ordinary value requires authorization for a named destination.

`ToolWorkflow` executes registered tools over governed inputs. Tool registration specifies the handler and its input and output schemas. The workflow validates requests, executes dependent calls in order, and publishes a final result after the required calls and release actions have completed.

The native llama.cpp integration controls access to encrypted input fields, verifies required tool completions, and publishes governed model outputs. The native runtime performs these checks within the inference service using its configured policies and keys.

`GovernedSQL` and `GovernedLazyFrame` publish SQL and Polars results as native TN publications. Query results, transformations, and aggregates retain source policies, original claim attribution, and contributor information for subsequent processing and recipient verification.

## Governed string through Polars

The example helper [`originate`](examples/local_policy.py) creates a `TNString` from `"alice"` under the supplied policy. `pl.Object` preserves that `TNString` instance in a regular Polars dataframe column. `map_elements` invokes `TNString.upper()` on the stored object; `Context` obtains a decision from its registered policy evaluator and completes required actions before decrypting the input within the runtime, computing the uppercase text, and encrypting the derived result.

`context` is a configured `Context` containing a native `Session`, a policy evaluator, and required-action handlers. The `Session` provides the keys and native publication operations. `Context` and `Endpoint` use the same `Request`/`Assessment` evaluator contract for value and artifact operations, respectively. `policy` is the selected source contract. The sequence returns a governed `TNString`; the separate `GovernedLazyFrame` interface covers governed dataframe expressions and plans.

```python
name = originate(context, "alice", policy, "name")
frame = pl.DataFrame({"name": [name]}, schema={"name": pl.Object})

with context:
    frame = frame.with_columns(
        frame["name"].map_elements(TNString.upper, return_dtype=pl.Object)
    )

result = frame["name"][0]
ciphertext = result.publication.object.envelope["values"]["ciphertext"]
print("Encrypted:", ciphertext)
print("Decrypted:", result.reveal(context, destination="console"))
```

The first print displays the encrypted content of the transformed value. `TNString.reveal()` obtains authorization for `console`, decrypts the value, and returns the ordinary string for the second print:

```text
Encrypted: twEBf9GbRFrI0kqGcAP4YXvWmpn6ReGXqSX+i1ooaVbt0z0AAAAAAAEAScZ1UzHZwNeAM351j/mKatkEWRg5h7z8gDY4h4N57IHb4isgmEhfh3jyfRWsoz7n5W1OPQAAACG/vsyi6uLcFdz7cOBm+AgyhshwCcd/JHj08P1Q9f8j2cU=
Decrypted: ALICE
```

### Policy in the same publication

The `string.processing` policy states the permitted operations, purpose, destination, and monitoring requirement. In this example, `evaluate(request)` is the evaluator registered on `Context`: it checks the requested use and adds the required `monitor` action to permitted decisions. `Context` invokes its registered monitoring handler to sign the record before protected processing. The transformed publication contains the source policy in its encrypted `tn.agents` group.

`Session.governance()` verifies the publication and decrypts its governance using the session's keys. `carried_policy.fields` contains the policy recovered from the publication:

```python
publication = result.publication.object
print("Encrypted policy:", publication.envelope["tn.agents"]["ciphertext"])
carried_policy = context.session.governance(publication).governance.policies[0]
print("Decrypted policy:", json.dumps(carried_policy.fields, indent=2))
```

```text
Encrypted policy: twEBrx+JrC3vFWN//oq0J2sHxEHj+V299IMLeiPbe/5sP14AAAAAAAEAF2vK95Xrtu2G+cqoRHV7Q1nScWz2OEtjTmwwbNsn+wMsYBqP6O8xsyYuwge85/arbi29hQAAA08CTQNfj7uvLkVFLRGhNdQ5zbep+/cCv+V9TGisu2kvZCh61uN/Of5GRe2vhpleKN4eeflMuotEn4fb/UJsA7yV/3sr+0K032RkkbxTt9hrlI5ibIGVlh6nPrjZNO9v/JLbC8BdiQ7MZvUqaICCGVuRUojOu/Jshoz/8hCUGnYVl1quYdVQpkGxp5BR3vBl889sJtSpbMx1jDzADEM655NxxwXQVRTv6HRX4Z3+UbpJ03BmzEw3WpvsnRBAzxZTlJDwu8S+Fi/+j1y7zHHZHuxbA9z3qhacUEsEiKpk/sK38fQCPIvUAY2k7UgW0ihcgj+agAn/vlxDX2vZhOQcAyUlXWoQS5YNSL6IK1uuVV8Bj1ZW8M8KDOLQjyZzz/QnUhGdOTTNsZvdEWbYDkzgs2gV0HZkULha4P6TYzs0j5A1T2wxoNWwkZBLTh/wNdn+Lq68P7vaPTFJaYlV9sV1kFc2/8JOZl23k4xDwQ/j7Kip7U2Soj6PPE6lgoMV8r6IUpYgh8GIHpfQvnmab7Vgc3xTqScLpZWKw4S2N09t1BGObN2zLn3qWz4Y00yOQ8NMRzgpKh6Q19Ur+ncEw7WEbl0q+dNz1ztawbO9B7X9Go0pdoCIpXRrWLXZ8leeagGIifIxzhu8NV9HLcPykIWGEBbqsjKRdk7p6tvX5lrPheyoLPNh7njI2kHcEo0jw4ykENOGMwHkZViq17v+Ndz/o2BquVRSi1ut0+N5S7kiOaF0EQis0OAmOq8mEE1zyFJ/aZ7/4CrN9d00AdjS3Zzqneb7Io4MbWIsi2CwNrxY4hf4k/RWEVTnyh3wlBps2aa8/ehDdg8+KvpnsD80eH1meLXOEfbYKoSgKro8VVvUSa2cfvZECqHo8OJZl7wVXJXmNWtQISBQxMpYE1IgExuClQV0QwGyObdLvEbviCfIfQuPSaec+7O6LbwipieUFQt4bUv2l/8s94vK21YyJDxnToSU50ajyzpvOF/OEN9V3krqjTcv/ADTFxIXcnT1Cz7/Yc12w9zkD5GzThsTNmvyC2jiOL6l10NHREkR3p4MKlDVHLm2EHy9sD2RmT+1fsimmtsBTIdGI9T9ZCA+SMhxpvqPDgrac1QOJEb9W7vrAquO
Decrypted policy: {
  "consequences": "Retain signed decisions, results, disclosures, and monitoring records.",
  "do_not_use_for": "Other applications, purposes, operations, or disclosure destinations.",
  "instruction": "Retain the source policy and input references when deriving a value.\nWrite a signed monitoring record before each protected operation.",
  "on_violation_or_error": "Record the refusal or failure and stop the protected operation.",
  "policy": "string_processing.policy#string.processing@1#sha256:1e882ad84e8347a94e8a88ba1a47349aa3cad99efece907594f66b4dbd43415e",
  "use_for": "The string-polars application may create and uppercase strings for the\nnormalization purpose. Ordinary output may be disclosed to console."
}
```

The [runnable example](examples/string_polars.py) includes the imports, [policy](examples/string_processing.policy), and endpoint configuration:

```sh
uv run python examples/string_polars.py
```

## Installation

Build requirements are Python 3.12, uv, Rust 1.95 or newer, and a C/C++ toolchain. `uv sync` builds the included TN SDK through Maturin and installs the Polars adapter and model client. Environment creation from the repository root:

```sh
uv sync --locked --extra dev
uv run python scripts/runtime_sources.py
```

Windows source builds require the Visual Studio C++ Build Tools; Linux source builds require a system C/C++ toolchain. On Windows, `scripts/run_submission.py` starts the Linux inference server through WSL.

`examples/governed_tools.py` requires this Python environment.

Automatic Unity installation requires Docker running Linux containers. SQL/dataframe execution needs OPA, and report generation needs a compatible GGUF model. The dependency discovery directory is `.runtime/dependencies/`, which is excluded from Git. `TN_POLARS_OPA` specifies the OPA executable.

The `scripts/install.py --tn-wheel PATH` installer also supports the pinned prebuilt Windows wheel described in `config/sdk-build.json`.

The SQL/dataframe runs also require:

- A local Java Unity Catalog service, reachable at `http://127.0.0.1:8080` or the address passed with `--unity-url`. `experiments.paper_evaluation.run` creates a uniquely named catalog and registers signed source assignments and editions. The catalog service must permit these requests. `UnityGovernance` verifies assignments under the configured authority.
- An OPA executable, on `PATH` or selected through `TN_POLARS_OPA`. The adapter compiles the evaluator to Wasm and executes it with Wasmtime.

```powershell
$env:TN_POLARS_OPA = (Resolve-Path .runtime/dependencies/opa.exe).Path
```

The TN-enabled server source is included under `native/tn-llama`: the Rust governance runtime, TN cryptography, C++ integration, and the llama.cpp patch. The build script fetches llama.cpp at the pinned commit and links these components into `llama-server`. The Python transport client is under `dependencies/tn-llama-client`. Native inference requires a compatible GGUF model file.

`scripts/run_submission.py` starts the Linux server through WSL using drive-backed Windows paths. The build and launcher use the default WSL distribution unless `TN_WSL_DISTRO` specifies another installed distribution.

The Rust `tn-runtime` crate verifies incoming TN publications, authorizes field access, executes required tools, and publishes encrypted model outputs containing source governance. `server-tn.cpp` integrates these checks with llama.cpp inference.

- [Native inference integration](native/tn-llama/src/llama/server-tn.cpp)
- [Session and model transitions](native/tn-llama/crates/tn-runtime/src/session/mod.rs)
- [Governed input verification](native/tn-llama/crates/tn-runtime/src/governed_input.rs)
- [Signed report publication](native/tn-llama/crates/tn-runtime/src/output_tn.rs)

### Build the included model server

The WSL build requires Git, CMake 3.24 or newer, Ninja, a C++ compiler, Python 3, and Rust 1.95 or newer. A CUDA build also requires the NVIDIA CUDA Toolkit with `nvcc` on PATH. CPU builds do not require CUDA.

Server build and example execution from the repository root in PowerShell:

```powershell
py -3.12 scripts/run_submission.py --build-server cpu --run-directory experiments/results/full-report
```

`--build-server cuda` selects GPU inference. CUDA builds target the installed GPU; `TN_CUDA_ARCHITECTURES` accepts a CMake architecture list for another target. `TN_BUILD_JOBS` controls compiler parallelism (default: 4). Direct CPU server build from a Linux shell:

```bash
bash scripts/build_llama.sh cpu
```

`scripts/build_llama.sh` installs `llama-server` and its shared libraries together in `.runtime/dependencies/tn-llama/`. `scripts/run_submission.py` discovers the server in that directory. Server distribution requires the executable and its shared libraries together. `build.json` records the backend and SHA-256 of every installed binary and library. `native/tn-llama/source-manifest.json` identifies the included source files and upstream revisions. Model weights are not downloaded by the build.

Before compilation, `scripts/build_llama.sh` invokes `scripts/runtime_sources.py` to verify the source manifest. `python scripts/runtime_sources.py --against PATH` compares a separate runtime checkout. `--refresh` updates source digests; when `--against` is specified, the comparison must succeed before the update. The Python SDK source is included under `native/tn-llama/upstream/tn-proto/python`; installation does not require a sibling repository or a private wheel download.

### Install Unity and run the complete example

`scripts/run_submission.py` creates a Python environment, installs the application,
starts the Java Unity Catalog service in Docker, and requests a report from the LLM.
The script verifies the returned report and pending-review registration.
Docker Desktop must be running with Linux containers, and WSL must be available
for the TN-enabled model server. The Unity image is pinned by digest.

Preconditions are the [configured dependencies](#installation), a pinned native wheel for `scripts/install.py`, and a built TN-enabled server. Launcher command:

```powershell
py -3.12 scripts/run_submission.py --run-directory experiments/results/full-report
```

`--dependency-dir` specifies an alternative directory for external dependencies. Individual command-line options override environment variables, which
override discovery in the dependency directory:

| File | Environment variable | Command-line override |
| --- | --- | --- |
| Native TN wheel | `TN_WHEEL` | `--tn-wheel` |
| OPA | `TN_POLARS_OPA` | `--opa` |
| TN-enabled model server | `TN_LLAMA_BINARY` | `--binary` |
| GGUF model | `TN_LLAMA_MODEL` | `--model-path` |

OPA can also be found on `PATH`. The launcher does not select an arbitrary
`llama-server` from `PATH`: it must be the TN-enabled server. A dependency
directory containing multiple GGUF models requires an explicit model selection. Relative paths
supplied on the command line or through environment variables are resolved from
the process working directory; the default dependency directory is relative to the checkout.
Invalid explicit paths produce an error rather than falling back to another file.

The launcher installs Unity automatically; model and native runtime files are
supplied separately. The default example uses one Decimal row.
`--numeric-type int` and `--numeric-type float` select the alternative numeric types.

`--unity-url http://127.0.0.1:8080` selects a running Java Unity service.
`scripts/run_submission.py` leaves an explicitly selected service running. A Unity container created by the launcher
is stopped when the run finishes; its container and data volume are retained.
The generated report is `report.html` and its review registration is `review.json`
in the selected run directory. Any failed generation or verification returns an error.

Unity installation on the SQL and numeric examples' default port:

```powershell
py -3.12 scripts/install_unity.py --port 8080
```

`scripts/install_unity.py` pulls the official `unitycatalog/unitycatalog` image, which includes
Java, and publishes its API only on `127.0.0.1`. `scripts/install_unity.py` creates a local demonstration
catalog with catalog-service authorization disabled; TN still verifies
signed source assignments. `scripts/install_unity.py` leaves an existing Unity installation intact.
`scripts/install_unity.py` prints the container name and URL. Container lifecycle commands are
`docker stop tn-submission-unity` and `docker start tn-submission-unity`.

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

[governed_tools.py](examples/governed_tools.py) loads [tool_workflow.policy](examples/tool_workflow.policy), originates the value `12`, attaches a claim, and registers a scaling handler. The example registers `evaluate(request)` as the policy evaluator on `Endpoint`. `Endpoint` invokes that callback to check the application, purpose, permitted operations, recognized writer, source contract, and disclosure destination. The registered tool multiplies the value by `3`; the final JSON output is `{"scaled": 36}`.

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

`ToolWorkflow.execute()` returns a `ToolCompletion`. Its `artifact` field contains the governed result, and its `handle` field contains the result identifier `result:scaled` for subsequent calls. `ToolWorkflow.finish(value, schema=..., destination=...)` validates and publishes the final workflow artifact. `Endpoint.reveal(artifact, destination=...)` returns an ordinary value after destination-specific authorization. `workflow.expose(completion.handle, destination=...)` resolves the result handle and invokes the same disclosure operation.

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

## Evaluation

The paper's evaluation drivers are in `experiments/paper_evaluation`.

### Compare processing cost

With Python, OPA, and Unity configured as described in [Installation](#installation), run:

```powershell
python -m experiments.paper_evaluation.processing_comparison --run-directory experiments/results/processing-comparison/example --rows 128 512 1024 --repetitions 3
```

Choose an output directory that does not already exist. Use `--unity-url` when Unity runs at a different address.

The experiment compares ordinary SQLite/Polars processing, explicit TN input tracking, and automatic TN input tracking. Each uses the same integer rows, SQL query, dataframe operations, scalar increment, and output string. Both TN modes use the same SQL and dataframe controls; they differ in how scalar operations supply their input references.

The SQL-to-string time covers the query, dataframe calculation, scalar operations, and return of the ordinary output string. In TN, the query also encrypts, signs, publishes, and registers the source values, then admits them at the consumer. The full path includes claim attachment and disclosure. Scalar time measures only the operations after the dataframe calculation. Setup, record export, and offline verification are recorded separately. The ordinary case has no governed publication or governance verification. Each TN case uses fresh sessions, assignments, and native objects. Mode order rotates across repetitions; one ordinary warmup initializes Polars, and Unity starts before measurement.

`measurements.json` contains every observation and the median, minimum, and maximum for each configuration. `processing_comparison.py` checks the calculated result, runs the offline verifiers for each TN execution, and records the final TN publication size.

### Scale, recipients, and tool depth

`config/performance.json` defines 1,000/10,000/100,000 input rows, 1/4/8 concurrent recipients on a 10,000-row publication, and application-tool depths 1/3/5 on 1,000 rows. Scale and depth use five measured repetitions after one warmup per configuration. Recipients use 30 measured rounds after one warmup. `config/performance-smoke.json` exercises the same driver with eight rows, one repetition, two recipient rounds, and depths 1/3.

Build CPU servers from the pinned llama.cpp revision. The ordinary build disables the TN integration while retaining the inference engine:

```powershell
wsl -d Ubuntu -- bash /mnt/c/path/to/tn-governed/scripts/build_llama.sh cpu
wsl -d Ubuntu -- bash /mnt/c/path/to/tn-governed/scripts/build_plain_llama.sh
```

Copy `config/performance-environment.example.json` to `.runtime/performance-local.json` and set the local Python, OPA, model, server, Unity URL, and WSL distribution. Start Unity using the setup instructions, then run:

```powershell
.\scripts\run-performance.ps1 -PreflightOnly
.\scripts\run-performance.ps1 -Profile smoke
.\scripts\run-performance.ps1 -Profile full
```

The scale workload performs the SQL query, source publication and admission, claim attachment, governed Polars filtering/sorting/aggregation, scalar composition, explicit disclosure, model preparation, native generation, recipient acceptance, and review registration. The plain path executes the same ordinary SQL/Polars/scalar calculation and generates an HTML report from the same business input. Both use the same GGUF, CPU execution, disabled prompt caching, temperature zero, and a 2,048-token report ceiling. TN also verifies governance natively and executes required actions. Each model decision receives its applicable governance context. Raw model transcripts and ordinary token counts are retained.

Reported processing time sums the query through disclosure and the generation/release stages. Source database creation, enrollment, catalog assignment, native endpoint configuration (including model-file hashing and ancestry serialization), model startup, offline verification, and artifact export are timed separately and excluded from processing latency. Working publications and records remain native objects in memory; `publications/` is a file archive written after the processing stages. The `export` timer records that boundary. Each scale case creates fresh sessions, native objects, and a model process; the operating-system file cache is retained. Warmup observations remain in the raw files and are excluded from summaries. Mode order alternates across repetitions.

Recipients run in separate spawned processes with distinct signing identities, reader kits, native object collections, local catalogs, and evaluators. The recipient worker in `performance_recipients.py` admits the received scalar, verifies its ancestry, obtains disclosure authorization, decrypts the value, retains the signed decision in memory, and validates the result. Enrollment, publication transfer, and catalog admission precede the timed interval. Each response carries its signed native records, serialized after the request timer. Batch wall time includes dispatch, barrier synchronization, evidence serialization, and result collection. Throughput is successful requests divided by total measured batch wall time; median and nearest-rank p95 use individual successful request latencies. Failed attempts remain visible.

Each tool-depth trial executes the full data/model path afresh. Depth counts the native compliance tool plus dependent review-registration tools. The latter consume the accepted report and then each predecessor receipt; a signed ledger action gates release. The native runtime verifies governance before the first model turn. That turn holds the governance and the hash keys of the encrypted data, and `decrypt_value` is its only tool. The model passes the governance hash key and the data hash keys it needs, and the runtime compares them with the admitted object and returns the values as the tool result. The runtime then executes a sole required action whose closed schema admits only an empty argument object. These steps retain authorization, publication verification, and runtime action records. The model handles the decrypt call and report content; application-tool depth counts the executed tools. The tool endpoint applies an explicit local grant for the named application, purpose, operations, and destinations while retaining the source contracts and claims.

`experiment.json` records parameters, hardware, versions, source and binary hashes, and timing boundaries. `samples.jsonl`, `scale.json`, recipient `rounds.jsonl`, and tool trial files retain observations and signed evidence. Byte accounting distinguishes the scalar publication from unique retained native bytes, including snapshots, metadata, and signed records; decimal KB means 1,000 bytes. Signed recorder counts and native model tool publications are separate quantities. Run directories contain local synthetic enrollment material and remain excluded from Git.

Runtime resource bounds are explicit profile parameters. Python preparation, native admission, recipient acceptance, and offline verification use the configured lineage limits. The submitted request's actual serialized size is checked against its configured byte limit before model transport.

Both profiles use 256 compatible cells per SQL publication, retaining a distinct field reference and signed result for each cell. The 100,000-row workload therefore uses 782 source publications and 200,000 direct cell references. Profile validation checks the required dataset-binding count against the native bound before processing begins.

The runtime retains and verifies full native governance and ancestry. In the model presentation, provenance arrays with more than 16 entries become references bound to the source publication, field, entry count, and authenticated field commitment. Policy text, attached contracts, claims, conditions, and extension fields remain present. Each model decision receives the verified source governance and accepted tool dependencies. The runtime binds that context to the issued request, rendered prompt, token manifest, and execution identity before inference. Determined actions appear as runtime results, without fabricated model calls. The model produces selections and tool arguments when a choice remains, and generates report content; the runtime constructs authoritative metadata, verifies receipts, and gates release. Released publications retain the complete source bindings. Report evidence verification requires the last inference, its emission and completion records, and a retained release matching the received publication.

### Check policy accumulation

After Python setup, configure OPA as described in [Installation](#installation). Run the six cases in a directory that does not already exist:

```powershell
python -m experiments.paper_evaluation.policy_accumulation --run-directory experiments/results/policy-accumulation/example
```

These checks use SQLite, native TN encryption and signatures, and real OPA evaluation. A local catalog resolves signed assignments and editions. They vary the number of rows, selected rows, and source tables, with two column policies per table under one catalog authority.

The `policy_accumulation.py` output contains policy revision IDs, input references, original claim attribution, observed aggregate membership, and publication size. The checks compare the aggregate's policies with the exact union of its inputs' policies. Increasing rows retains the same policies while adding input references. Adding source tables adds distinct policies. Adding an aggregate to itself preserves its policies and claim identity, with both operand references recorded.

In the cases with multiple source tables, one table permits disclosure only to `review-console`. Its rows are filtered out, but its condition still applies to the aggregate. Disclosure to `analysis-console` stops before content opens; `review-console` receives the calculated value. The signed operation records are verified and exported with each case.

Run the accumulation and adjacent dataframe checks with:

```powershell
python -m pytest tests/test_policy_accumulation.py tests/test_query_dataframe.py -q
```

### Check dataframe edge cases

`experiments/paper_evaluation/edge_cases.py` runs fixtures with negative amounts, unsorted names, duplicate sort ties, and an empty selection through the governed SQL and dataframe path. `edge_cases.py` compares each result with a calculation made outside the plan and runs the offline verifiers. `--with-model` adds a `Decimal` report through the governed server.

```powershell
python -m experiments.paper_evaluation.edge_cases --run-directory experiments/results/edge-cases
```

### Check recipient decisions and review completion

With the project environment and its development dependencies installed, run:

```powershell
python -m pytest tests/test_recipient_authority.py tests/test_report_review_completion.py -q
```

These tests use native encryption and signatures. Independent recipient Sessions receive the same publication and decide according to their own purpose and recognized writer. The checks distinguish permission from possession of a decryption key, verify original claim attribution after another transformation, and reject changes to encrypted content or governance. Report tests cover native objects and file-archive compatibility, including a recipient that verifies the carried report after access to the sender's object collection is disabled.

The report tests use constructed, signed tool and report publications returned by a local transport. They exercise the production recipient and review-registration code. A successful call returns after the recipient accepts the report and the application writes a signed pending-review request to the queue. Recipient refusal, failure to append the signed record, or failure to write the queue prevents success and produces a signed Failure. A retry is recorded as a separate call. The [full model example](#install-unity-and-run-the-complete-example) runs the model service.

### Check the model runtime under faults

`experiments/paper_evaluation/runtime_faults.py` runs the SQL-to-report path with a fresh server and the real model for each case. Route faults change the HTTP request, and configuration faults change the runtime configuration or metadata before server start. Task faults change the prepared task between preparation and the slot gate, and result faults change a completed model result before the runtime validates it. Those two groups use a test server built by `experiments/paper_evaluation/fault_injection/build_fault_server.sh`, whose hooks are absent from the packaged server. Adversarial prompts and a company name containing an instruction use the packaged server, and the same inputs run through the plain server as a baseline.

```bash
bash experiments/paper_evaluation/fault_injection/build_fault_server.sh
python -m experiments.paper_evaluation.runtime_faults --run-directory experiments/results/runtime-faults \
  --binary .runtime/dependencies/tn-llama/llama-server \
  --fault-binary .runtime/dependencies/tn-llama-fault/llama-server \
  --plain-binary .runtime/llama-build/plain-cpu/bin/llama-server \
  --model-path .artifacts/models/Qwen3-4B-Q4_K_M.gguf \
  --sdk-build-record .runtime/sdk-build-linux.json
```

Each case records whether a task reached a slot, the tokens decoded, the refusal codes, and whether a report and review request exist. `context_sensitivity.py` measures prompt tokens and inference time across provenance entries and claims.

### Check the verifiers with mutants

`experiments/paper_evaluation/propagation_mutants.py` changes one step of a live run so the endpoint's keys sign an incorrect output, then records whether the runtime stopped it and whether the offline verifiers reject the evidence. `evidence_mutants.py` alters retained evidence, including model traces and audit logs, without keys. Pass `--model-baseline` with a completed model run to include the model family. The evaluation's expected-value comparison is reported separately and is not counted as detection.

### Compare relation and cell granularity

`experiments/paper_evaluation/relation_study.py` measures the query-result path on the market workload and on TPC-H-shaped data from `tpch_data.py`, which is derived from the specification and is not an audited TPC-H implementation. `GovernedSQL.execute_query(sql, contributor_tracking=False)` records source columns and unknown row support in place of contributor rows. Contributor cases run in their own process so exhausted memory is a recorded outcome.

`scripts/setup_linux_evaluation.sh` prepares an Ubuntu 24.04 host from prebuilt servers and the Linux SDK wheel. Archive export performs one `fsync` per file; large runs can use `eatmydata`, since export is excluded from processing time.

Research paper: *TN: Data Governance That Travels Through SQL, Dataframe, and LLM Pipelines*.
