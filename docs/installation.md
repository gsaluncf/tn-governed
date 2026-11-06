# Installation and native builds

## Setup

Build requirements are Python 3.12, uv, Rust 1.95 or newer, and a C/C++ toolchain. `uv sync` builds the included TN SDK through Maturin and installs the Polars adapter and model client. Environment creation from the repository root:

```sh
uv sync --locked --extra dev
uv run python scripts/runtime_sources.py
```

Windows source builds require the Visual Studio C++ Build Tools; Linux source builds require a system C/C++ toolchain. On Windows, `scripts/run_submission.py` starts the Linux inference server through WSL.

Automatic Unity installation requires Docker running Linux containers. SQL/dataframe execution needs OPA, and report generation needs a compatible GGUF model. The dependency discovery directory is `.runtime/dependencies/`, which is excluded from Git. `TN_POLARS_OPA` specifies the OPA executable.

The `scripts/install.py --tn-wheel PATH` installer also supports the pinned prebuilt Windows wheel described in `config/sdk-build.json`.

The SQL/dataframe runs also require:

- A local Java Unity Catalog service, reachable at `http://127.0.0.1:8080` or the address passed with `--unity-url`. `experiments.pvldb_evaluation.run` creates a uniquely named catalog and registers signed source assignments and editions. The catalog service must permit these requests. `UnityGovernance` verifies assignments under the configured authority.
- An OPA executable, on `PATH` or selected through `TN_POLARS_OPA`. The adapter compiles the evaluator to Wasm and executes it with Wasmtime.

```powershell
$env:TN_POLARS_OPA = (Resolve-Path .runtime/dependencies/opa.exe).Path
```

The TN-enabled server source is included under `native/tn-llama`: the Rust governance runtime, TN cryptography, C++ integration, and the llama.cpp patch. The build script fetches llama.cpp at the pinned commit and links these components into `llama-server`. The Python transport client is under `dependencies/tn-llama-client`. Native inference requires a compatible GGUF model file.

`scripts/run_submission.py` starts the Linux server through WSL using drive-backed Windows paths. The build and launcher use the default WSL distribution unless `TN_WSL_DISTRO` specifies another installed distribution.

The Rust `tn-runtime` crate verifies incoming TN publications, authorizes field access, executes required tools, and publishes encrypted model outputs containing source governance. `server-tn.cpp` integrates these checks with llama.cpp inference.

- [Native inference integration](../native/tn-llama/src/llama/server-tn.cpp)
- [Session and model transitions](../native/tn-llama/crates/tn-runtime/src/session/mod.rs)
- [Governed input verification](../native/tn-llama/crates/tn-runtime/src/governed_input.rs)
- [Signed report publication](../native/tn-llama/crates/tn-runtime/src/output_tn.rs)

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

## Install Unity and run the complete example

`scripts/run_submission.py` creates a Python environment, installs the application,
starts the Java Unity Catalog service in Docker, and requests a report from the LLM.
The script verifies the returned report and pending-review registration.
Docker Desktop must be running with Linux containers, and WSL must be available
for the TN-enabled model server. The Unity image is pinned by digest.

Preconditions are the [configured dependencies](installation.md#setup), a pinned native wheel for `scripts/install.py`, and a built TN-enabled server. Launcher command:

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
