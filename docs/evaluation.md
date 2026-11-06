# Evaluation

## Compare processing cost

With Python, OPA, and Unity configured as described in [Installation](installation.md#setup), run:

```powershell
python -m experiments.pvldb_evaluation.processing_comparison --run-directory experiments/results/processing-comparison/example --rows 128 512 1024 --repetitions 3
```

Choose an output directory that does not already exist. Use `--unity-url` when Unity runs at a different address.

The experiment compares ordinary SQLite/Polars processing, explicit TN input tracking, and automatic TN input tracking. Each uses the same integer rows, SQL query, dataframe operations, scalar increment, and output string. Both TN modes use the same SQL and dataframe controls; they differ in how scalar operations supply their input references.

The SQL-to-string time covers the query, dataframe calculation, scalar operations, and return of the ordinary output string. In TN, the query also encrypts, signs, publishes, and registers the source values, then admits them at the consumer. The full path includes claim attachment and disclosure. Scalar time measures only the operations after the dataframe calculation. Setup, record export, and offline verification are recorded separately. The ordinary case has no governed publication or governance verification. Each TN case uses fresh sessions, assignments, and native objects. Mode order rotates across repetitions; one ordinary warmup initializes Polars, and Unity starts before measurement.

`measurements.json` contains every observation and the median, minimum, and maximum for each configuration. `processing_comparison.py` checks the calculated result, runs the offline verifiers for each TN execution, and records the final TN publication size.

## Scale, recipients, and tool depth

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

## Check policy accumulation

After Python setup, configure OPA as described in [Installation](installation.md#setup). Run the six cases in a directory that does not already exist:

```powershell
python -m experiments.pvldb_evaluation.policy_accumulation --run-directory experiments/results/policy-accumulation/example
```

These checks use SQLite, native TN encryption and signatures, and real OPA evaluation. A local catalog resolves signed assignments and editions. They vary the number of rows, selected rows, and source tables, with two column policies per table under one catalog authority.

The `policy_accumulation.py` output contains policy revision IDs, input references, original claim attribution, observed aggregate membership, and publication size. The checks compare the aggregate's policies with the exact union of its inputs' policies. Increasing rows retains the same policies while adding input references. Adding source tables adds distinct policies. Adding an aggregate to itself preserves its policies and claim identity, with both operand references recorded.

In the cases with multiple source tables, one table permits disclosure only to `review-console`. Its rows are filtered out, but its condition still applies to the aggregate. Disclosure to `analysis-console` stops before content opens; `review-console` receives the calculated value. The signed operation records are verified and exported with each case.

Run the accumulation and adjacent dataframe checks with:

```powershell
python -m pytest tests/test_policy_accumulation.py tests/test_query_dataframe.py -q
```

## Check dataframe edge cases

`experiments/pvldb_evaluation/edge_cases.py` runs fixtures with negative amounts, unsorted names, duplicate sort ties, and an empty selection through the governed SQL and dataframe path. `edge_cases.py` compares each result with a calculation made outside the plan and runs the offline verifiers. `--with-model` adds a `Decimal` report through the governed server.

```powershell
python -m experiments.pvldb_evaluation.edge_cases --run-directory experiments/results/edge-cases
```

## Check recipient decisions and review completion

With the project environment and its development dependencies installed, run:

```powershell
python -m pytest tests/test_recipient_authority.py tests/test_report_review_completion.py -q
```

These tests use native encryption and signatures. Independent recipient Sessions receive the same publication and decide according to their own purpose and recognized writer. The checks distinguish permission from possession of a decryption key, verify original claim attribution after another transformation, and reject changes to encrypted content or governance. Report tests cover native objects and file-archive compatibility, including a recipient that verifies the carried report after access to the sender's object collection is disabled.

The report tests use constructed, signed tool and report publications returned by a local transport. They exercise the production recipient and review-registration code. A successful call returns after the recipient accepts the report and the application writes a signed pending-review request to the queue. Recipient refusal, failure to append the signed record, or failure to write the queue prevents success and produces a signed Failure. A retry is recorded as a separate call. The [full model example](examples.md#run-the-complete-modelreport-workflow) runs the model service.

## Check the model runtime under faults

`experiments/pvldb_evaluation/runtime_faults.py` runs the SQL-to-report path with a fresh server and the real model for each case. Route faults change the HTTP request, and configuration faults change the runtime configuration or metadata before server start. Task faults change the prepared task between preparation and the slot gate, and result faults change a completed model result before the runtime validates it. Those two groups use a test server built by `experiments/pvldb_evaluation/fault_injection/build_fault_server.sh`, whose hooks are absent from the packaged server. Adversarial prompts and a company name containing an instruction use the packaged server, and the same inputs run through the plain server as a baseline.

```bash
bash experiments/pvldb_evaluation/fault_injection/build_fault_server.sh
python -m experiments.pvldb_evaluation.runtime_faults --run-directory experiments/results/runtime-faults \
  --binary .runtime/dependencies/tn-llama/llama-server \
  --fault-binary .runtime/dependencies/tn-llama-fault/llama-server \
  --plain-binary .runtime/llama-build/plain-cpu/bin/llama-server \
  --model-path .artifacts/models/Qwen3-4B-Q4_K_M.gguf \
  --sdk-build-record .runtime/sdk-build-linux.json
```

Each case records whether a task reached a slot, the tokens decoded, the refusal codes, and whether a report and review request exist. `context_sensitivity.py` measures prompt tokens and inference time across provenance entries and claims.

## Check the verifiers with mutants

`experiments/pvldb_evaluation/propagation_mutants.py` changes one step of a live run so the endpoint's keys sign an incorrect output, then records whether the runtime stopped it and whether the offline verifiers reject the evidence. `evidence_mutants.py` alters retained evidence, including model traces and audit logs, without keys. Pass `--model-baseline` with a completed model run to include the model family. The evaluation's expected-value comparison is reported separately and is not counted as detection.

## Compare relation and cell granularity

`experiments/pvldb_evaluation/relation_study.py` measures the query-result path on the market workload and on TPC-H-shaped data from `tpch_data.py`, which is derived from the specification and is not an audited TPC-H implementation. `GovernedSQL.execute_query(sql, contributor_tracking=False)` records source columns and unknown row support in place of contributor rows. Contributor cases run in their own process so exhausted memory is a recorded outcome.

`scripts/setup_linux_evaluation.sh` prepares an Ubuntu 24.04 host from prebuilt servers and the Linux SDK wheel. Archive export performs one `fsync` per file; large runs can use `eatmydata`, since export is excluded from processing time.
