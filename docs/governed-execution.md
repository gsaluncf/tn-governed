# Governed execution

`Endpoint` combines a native TN session, an in-memory publication store, an authority evaluator, required-action handlers, and a signed evidence recorder. Each instance has its own keys and authority configuration. Native TN publications contain encrypted values, source policies, original claims, and direct input references.

## Execution and disclosure

`Endpoint.execute(operation, inputs, compute, parameters=..., destination=...)` accepts `GovernedArtifact` inputs and a computation callback. Before invoking `compute`, `Endpoint.execute()` verifies the input publications and ancestry, constructs a `Request`, obtains an `Assessment` from the configured evaluator, and completes required actions. After authorization, `compute` receives a tuple of ordinary values. `Endpoint.execute()` publishes the returned JSON as an encrypted, signed `GovernedArtifact` with the contributing policies, claims, and input references.

`Endpoint.reveal(artifact, destination=...)` requires authorization for the named destination and returns an ordinary value with a signed disclosure record. `GovernedBoundary` requires governed inputs and rejects ordinary values, including outputs of `Endpoint.reveal()`.

`Endpoint.export()` serializes native publications and supporting evidence into an `ArtifactBundle`. `Endpoint.receive()` verifies the bundle under the receiving instance's authority configuration and returns an admitted artifact. Computation uses the in-memory publications; serialization occurs at explicit export boundaries.

## Authority and required actions

An endpoint evaluator accepts a `Request` and returns an `Assessment` containing a decision and ordered required actions. `AuthorityEvaluator` evaluates matching source contracts using configured conjunction or authority precedence. Its assessment includes the contributing votes, selected precedence, claim judgments, and action order. `AuthorityEvaluator` validates action dependencies and refuses incompatible actions or cycles.

`Endpoint` invokes configured action handlers in the required order. A handler returns `ObligationResult(satisfied, evidence)`; successful completion requires `satisfied=True` and a nonempty evidence reference. `Endpoint` signs each returned action result before invoking the next handler. If a later handler fails, `Endpoint` retains the earlier signed observations and stops protected execution. External action handlers implement idempotency, retry, and compensation for their side effects.

## Claims and value history

`Endpoint.attest()` creates a signed claim about a governed artifact. `Endpoint.dispute()` creates a separately attributed statement referencing an original claim. Derived publications preserve the original claim author and subject.

`ValueHistory(endpoint)` retains artifacts and signed successor transitions in memory. Insertions, re-derivations, tombstones, and restorations use atomic predecessor checks. A tombstoned version cannot be used as an active value. Restoration requires an active replacement and retains references to the deleted predecessor and replacement.

`ValueHistory.export()` returns a `HistorySnapshot`; `export(path)` also writes an atomic checkpoint of the native publication bytes. `ValueHistory.receive(snapshot, endpoint)` verifies signed transitions before installing local heads. `ValueHistory(path, endpoint)` configures an explicit export destination without reading or writing during computation.

## Adapter admission

`Endpoint.import_publication()` accepts a native field reference, verified claim identifiers, the required supporting publications, and an optional content validator. `Endpoint` obtains authorization and completes required actions before opening content or invoking the validator. Accepted claim subjects must reference signed fields in the source ancestry. `Endpoint.receive()` also retains parent decisions and completed-action evidence for native artifacts.

`tn_polars.import_frame(endpoint, publication, publications=...)` authenticates encrypted audit metadata, resolves signed claims, and validates business rows after endpoint authorization. The resulting artifact includes the dataframe audit in signed operation parameters. Re-admission preserves upstream audit records and declared contributor precision.

## Implementation modules

| Component | Inputs, operation, and output |
| --- | --- |
| `GovernedSQL` in `values/sql.py`, `query.py`, and `query_result.py` | Accepts SQL and typed parameters, resolves source policies and dependencies, and publishes signed positional query results. |
| `GovernedLazyFrame` in `dependencies/tn-polars/tn_polars` | Accepts admitted dataframe publications and registered expressions or plans; returns governed frames and signed releases with contributor metadata. |
| `ToolWorkflow` in `tool_runtime.py` | Accepts registered `Call` records over governed inputs; returns validated tool completions and a governed workflow result after release checks. |
| `AuthorityEvaluator` in `endpoint_policy.py` | Accepts a requested use and source contracts; returns local policy judgments and ordered required actions. |
| `GovernedBoundary` in `boundaries.py` | Validates governed input handles before passing artifacts to a protected operation. |
| `ValueHistory` in `value_history.py` | Applies signed value transitions with predecessor checks; returns retained versions and exportable snapshots. |

`tests/test_governed_pipeline.py` verifies SQL, Polars, claims, dependent tools, a required ledger action, and recipient verification using separate sessions and stores. Component tests cover contributor mappings, exact value transport, refusals, partial action failures, authority precedence, concurrent endpoints, and value history.
