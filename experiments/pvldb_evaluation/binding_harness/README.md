# Binding evaluation harness

These scripts produced the evaluation rounds of the governance-binding work on 2026-11-04, in WSL 2 (Ubuntu 24.04, CUDA 12.9) on a workstation with an Intel Core i7-11700K and an NVIDIA RTX 3060. They expect the assembled tree in `~/tn-cuda/binding/tn-governed`, the model in `~/tn-cuda/models`, and results in `~/tn-cuda/results`.

| Script | What it does |
|---|---|
| `binding-tree.sh prepare` | Assembles `~/tn-cuda/binding/tn-governed` from the three checkouts in `$BINDING_SOURCES`, including `native/tn-llama`, and records its source manifest with `native_manifest.py` (`PROTO_COMMIT` and `LLAMA_COMMIT` name the commits). `VENDORED_NATIVE` names an existing `native/tn-llama` for the llama.cpp patches, headers, and sources. |
| `binding-tree.sh venv`, `sdk`, `native`, `smoke` | Builds the virtual environment, the tn-proto wheel with maturin (recorded in `.runtime/sdk-build-linux.json`), and the CUDA model server, then runs an 8-row case with the model. |
| `binding-studies.sh [step...]` | Runs every study the paper reads into `~/tn-cuda/results/$ROUND`: native and Python tests, correctness cases, runtime faults, decrypt reliability, propagation mutants, context sensitivity, publication size, the performance profile in `config/performance.json`, and the relational studies. `ROUND` must name a new directory. It stops if the Windows drive has less than 10 GB free. |
| `rerun-config-faults.sh` | Reruns the fault study's configuration group into `binding-r2/runtime-faults-configuration`. |
| `compare-rounds.py`, `compare.sh` | Compares the pre-review round with a binding round, study by study. |
| `clean-numbers.sh`, `perf-summary.sh` | Prints a round's cost numbers: per-stage medians, ratios, recipients, and tool depths. |
| `fault-outcomes.py` | Tallies a round's fault outcomes per group (`ROUND` picks the round). |
| `mutant-diff.sh`, `context-turns.sh` | Compares mutant outcomes, per-turn token counts, and publication-size medians across rounds. |

## Rounds

- `binding-r2` is the clean round: every study on the final code with nothing else running on the machine. Its configuration faults are superseded by `binding-r2/runtime-faults-configuration`, run after the ancestor case was corrected.
- `binding-r1` was the shakedown round. Its correctness results stand; host builds overlapped some of its timed samples.
- `final` is the round before the review, which counted model generation inside processing.

## Sources

`prepare` reads three checkouts in `$BINDING_SOURCES`:

- `tn-proto-binding` is the tn-proto `governance-binding` branch at its binding commit (486958e, the scaling patch, and governance binding).
- `tn-llama-binding` holds the runtime crates of the tn-llama `governance-binding` branch; its Cargo files point at the sibling tn-proto checkout instead of the submodule, and `prepare` rewrites them to the vendored path.
- `tn-governed-binding` is this branch outside `native/`.

`native/tn-llama` on this branch is the assembled runtime the rounds built; its `source-manifest.json` names the tn-proto and tn-llama commits. This branch and the tn-proto commit are enough to rebuild the evaluated system.

The Linux wheel was `tn_proto 2026.9.13b1+486958e.scaling`, sha256 `a3ae0d6da3f0af21bb91a24c0a97e6e0589089ebf16619f709f816c0de9818a8`; `.runtime/sdk-build-linux.json` records it. `config/sdk-build.json` records the Windows build of the same sources. The model was `Qwen3-4B-Q4_K_M.gguf` with every layer on the GPU (`--gpu-layers 99`). Unity Catalog ran natively at 127.0.0.1:18080, with a second copy at 8080 for the scalar suite.
