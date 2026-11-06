# Installation and native builds

## Setup

Use Python 3.12, uv, Rust 1.95 or newer, and a C/C++ build toolchain. The locked environment builds the included TN SDK source and installs the included Polars adapter and model client. Run from the repository root:

```sh
uv sync --locked --extra dev
uv run python scripts/runtime_sources.py
```

On Windows, use the Visual Studio C++ Build Tools. Linux builds use the system C/C++ toolchain. The complete model example runs its Linux inference server through WSL on Windows.

Automatic Unity installation requires Docker running Linux containers. SQL/dataframe execution needs OPA, and report generation needs a compatible GGUF model. Keep external executables and model files under `.runtime/dependencies/`, which is excluded from Git. Select OPA with `TN_POLARS_OPA`.

The `scripts/install.py --tn-wheel PATH` installer also supports the pinned prebuilt Windows wheel described in `config/sdk-build.json`.

The SQL/dataframe runs also require:

- A local Java Unity Catalog service, reachable at `http://127.0.0.1:8080` or the address passed with `--unity-url`. The runner creates a uniquely named catalog and registers its signed source assignments and editions. Use a local development instance that permits these requests. The application checks the signed assignments under its configured authority.
- An OPA executable, on `PATH` or selected through `TN_POLARS_OPA`. The adapter compiles the evaluator to Wasm and executes it with Wasmtime.

```powershell
$env:TN_POLARS_OPA = (Resolve-Path .runtime/dependencies/opa.exe).Path
```

The TN-enabled server source is included under `native/tn-llama`: the Rust governance runtime, TN cryptography, C++ integration, and the llama.cpp patch. The build script fetches llama.cpp at the pinned commit and links these components into `llama-server`. The Python transport client is under `dependencies/tn-llama-client`. Supply your own compatible GGUF model weights.

The runner launches the Linux server through WSL using drive-backed Windows paths. Build and run use your default WSL distribution. Set `TN_WSL_DISTRO` if you want a different installed distribution.

Rust verifies incoming TN publications, controls when the model can read their contents, runs required tools, and releases encrypted reports with their source governance. The C++ integration connects those checks to llama.cpp's inference loop.

- [Native inference integration](../native/tn-llama/src/llama/server-tn.cpp)
- [Session and model transitions](../native/tn-llama/crates/tn-runtime/src/session/mod.rs)
- [Governed input verification](../native/tn-llama/crates/tn-runtime/src/governed_input.rs)
- [Signed report publication](../native/tn-llama/crates/tn-runtime/src/output_tn.rs)

### Build the included model server

In your chosen WSL distribution, install Git, CMake 3.24 or newer, Ninja, a C++ compiler, Python 3, and Rust 1.95 or newer. A CUDA build also requires the NVIDIA CUDA Toolkit with `nvcc` on PATH. CPU builds do not require CUDA.

From the repository root in PowerShell, build and run the complete example:

```powershell
py -3.12 scripts/run_submission.py --build-server cpu --run-directory experiments/results/full-report
```

Use `--build-server cuda` for GPU inference. CUDA builds target the installed GPU; set `TN_CUDA_ARCHITECTURES` to a CMake architecture list when building for another machine. `TN_BUILD_JOBS` controls compiler parallelism (default: 4). The same script can build the server directly from a Linux shell:

```bash
bash scripts/build_llama.sh cpu
```

The build installs `llama-server` **and its shared libraries** together in `.runtime/dependencies/tn-llama/`. The launcher discovers that server automatically. Keep the directory together when moving it. `build.json` records the backend and SHA-256 of every installed binary and library. `native/tn-llama/source-manifest.json` identifies the included source files and upstream revisions. Model weights are not downloaded by the build.

Before compiling, the build verifies the included source manifest. Run `python scripts/runtime_sources.py --against PATH` to compare a separate runtime checkout. `python scripts/runtime_sources.py --refresh` records digests for the included source; an explicit comparison must succeed before its digests can be refreshed. The Python SDK source is included under `native/tn-llama/upstream/tn-proto/python`; installation does not require a sibling repository or a private wheel download.

## Install Unity and run the complete example

The single-command launcher creates a Python environment, installs the application,
starts the Java Unity Catalog service in Docker, and requests a report from the LLM.
It checks the returned report and pending-review registration.
Docker Desktop must be running with Linux containers, and WSL must be available
for the TN-enabled model server. The Unity image is pinned by digest.

Use the external files listed in [Installation](installation.md#setup). After building the included server, run:

```powershell
py -3.12 scripts/run_submission.py --run-directory experiments/results/full-report
```

You can keep the files together elsewhere and pass `--dependency-dir` with that
directory. Individual command-line options override environment variables, which
override discovery in the dependency directory:

| File | Environment variable | Command-line override |
| --- | --- | --- |
| Native TN wheel | `TN_WHEEL` | `--tn-wheel` |
| OPA | `TN_POLARS_OPA` | `--opa` |
| TN-enabled model server | `TN_LLAMA_BINARY` | `--binary` |
| GGUF model | `TN_LLAMA_MODEL` | `--model-path` |

OPA can also be found on `PATH`. The launcher does not select an arbitrary
`llama-server` from `PATH`: it must be the TN-enabled server. If the dependency
directory contains multiple GGUF models, select one explicitly. Relative paths
supplied on the command line or through environment variables are resolved from
your current directory; the default dependency directory is relative to the checkout.
Invalid explicit paths produce an error rather than falling back to another file.

The launcher installs Unity automatically; model and native runtime files are
supplied separately. The default example uses one Decimal row.
Use `--numeric-type int` or `--numeric-type float` to select another numeric type.

To use your running Java Unity service, add `--unity-url http://127.0.0.1:8080`.
The launcher leaves that service running. A Unity container created by the launcher
is stopped when the run finishes; its container and data volume are retained.
The generated report is `report.html` and its review registration is `review.json`
in the selected run directory. Any failed generation or verification returns an error.

To install and start Unity on the port used by the SQL and numeric examples:

```powershell
py -3.12 scripts/install_unity.py --port 8080
```

The installer pulls the official `unitycatalog/unitycatalog` image, which includes
Java, and publishes its API only on `127.0.0.1`. It creates a local demonstration
catalog with catalog-service authorization disabled; TN still verifies
signed source assignments. It does not modify an existing Unity installation.
The installer prints the container name and URL. Stop it with
`docker stop tn-submission-unity`; restart it with `docker start tn-submission-unity`.
