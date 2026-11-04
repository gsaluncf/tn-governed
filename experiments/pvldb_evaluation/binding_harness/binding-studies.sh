#!/bin/bash
# Every study the paper reads, on the refactored binding harness; results go to a new directory.
# usage: ROUND=<new directory> binding-studies.sh [step...]   (no arguments runs every step)
set -uo pipefail
T=$HOME/tn-cuda/binding/tn-governed
R=$HOME/tn-cuda/results/${ROUND:?set ROUND to the name of a new results directory}
M=$HOME/tn-cuda/models/Qwen3-4B-Q4_K_M.gguf
SDK=.runtime/sdk-build-linux.json
UNITY=http://127.0.0.1:18080
mkdir -p "$R/correctness"
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:/usr/local/cuda/bin:/usr/lib/wsl/lib:/usr/bin:/bin"
export TN_POLARS_OPA=$T/.runtime/dependencies/opa POLARS_MAX_THREADS=16 PYTHONUNBUFFERED=1
export PYTHONPATH=$T/src:$T
PY=$T/.venv/bin/python
cd "$T" || exit 1

step() { echo "=== $(date -u +%H:%M:%S) $*"; }
guard() {
    local free; free=$(df -BG /mnt/c | awk 'NR==2 {gsub("G","",$4); print $4}')
    if [ "$free" -lt 10 ]; then echo "stop: C: has ${free} GB free"; exit 3; fi
}
wanted() { [ "${#STEPS[@]}" -eq 0 ] || [[ " ${STEPS[*]} " == *" $1 "* ]]; }
STEPS=("$@")
# The scalar suite and the numeric path use run_case's default Unity port.
unity_8080() {
    curl -sf -o /dev/null http://127.0.0.1:8080/api/2.1/unity-catalog/catalogs && return
    rm -rf "$HOME/tn-cuda/unity-8080" && cp -a "$HOME/tn-cuda/unity" "$HOME/tn-cuda/unity-8080"
    (cd "$HOME/tn-cuda/unity-8080" && nohup java @server.args --port 8080 > unity.log 2>&1 &)
    for _ in $(seq 1 90); do
        curl -sf -o /dev/null http://127.0.0.1:8080/api/2.1/unity-catalog/catalogs && return
        sleep 1
    done
    echo "Unity on 8080 did not start"; exit 4
}

if wanted fault-server; then
    step fault-server; guard
    TN_BUILD_JOBS=14 TN_CUDA_ARCHITECTURES=86 \
        bash experiments/pvldb_evaluation/fault_injection/build_fault_server.sh cuda > "$R/fault-server-build.log" 2>&1
    echo "build $?"; ls -la .runtime/dependencies/tn-llama-fault/llama-server
fi
if wanted native; then
    step native-tests; guard
    (cd native/tn-llama && cargo test --locked -p tn-runtime --no-fail-fast) > "$R/correctness/native-tests.log" 2>&1
    grep -E '^test result' "$R/correctness/native-tests.log" | awk '{p+=$4; f+=$6} END {print "passed", p, "failed", f}'
fi
if wanted python; then
    step python-tests; guard
    $PY -m pytest tests -q --tb=short --junitxml="$R/correctness/python-tests.xml" -p no:cacheprovider > "$R/correctness/python-tests.log" 2>&1
    tail -1 "$R/correctness/python-tests.log" | cut -c1-140
    $PY -m pytest tests/test_relational_paper_coverage.py tests/test_sql_lineage.py tests/test_sql_query_results.py \
        tests/test_polars_plans.py tests/test_query_dataframe.py tests/test_dataframe_audit.py -q --tb=short \
        --junitxml="$R/correctness/relational.xml" -p no:cacheprovider > "$R/correctness/relational.log" 2>&1
    tail -1 "$R/correctness/relational.log" | cut -c1-140
fi
if wanted correctness; then
    C=$R/correctness
    unity_8080
    step edge-cases; guard
    rm -rf "$C/edge-cases"
    $PY -m experiments.pvldb_evaluation.edge_cases --run-directory "$C/edge-cases" --unity-url $UNITY > "$C/edge-cases.log" 2>&1; echo "exit $?"
    # The in-package demo is retired; run.py's primitive mode is the one runnable flow.
    for kind in int Decimal; do
        step "case-$kind"; guard
        rm -rf "$C/case-$kind"
        $PY -m experiments.pvldb_evaluation.run --mode primitive --numeric-type $kind --rows 8 --unity-url $UNITY \
            --sdk-build-record $SDK --run-directory "$C/case-$kind" > "$C/case-$kind.log" 2>&1; echo "case $?"
        $PY -m tn_governed.values.verify "$C/case-$kind" > "$C/case-$kind-verify.log" 2>&1; echo "verify $?"
    done
    step decimal-report; guard
    $PY - "$C" <<'PY'
import json, sys
from pathlib import Path
from experiments.pvldb_evaluation.edge_cases import decimal_report
root = Path(sys.argv[1]) / "decimal"
root.mkdir(parents=True, exist_ok=True)
limits = json.loads(Path("config/performance.json").read_text())["runtime_limits"]
report = decimal_report(root, "http://127.0.0.1:18080", 18326,
                        binary=Path(".runtime/dependencies/tn-llama/llama-server"),
                        model_path=Path.home() / "tn-cuda/models/Qwen3-4B-Q4_K_M.gguf",
                        sdk_build_record=Path(".runtime/sdk-build-linux.json"), runtime_limits=limits)
(Path(sys.argv[1]) / "decimal-report.json").write_text(json.dumps(report, indent=2, default=str))
print(report)
PY
    step scalar-suite; guard
    rm -rf "$C/scalar-suite"
    $PY -m experiments.pvldb_evaluation.suite --directory "$C/scalar-suite" --repetitions 3 > "$C/scalar-suite.log" 2>&1
    tail -1 "$C/scalar-suite.log" | cut -c1-160
    step policy-accumulation; guard
    rm -rf "$C/policy-accumulation"
    $PY -m experiments.pvldb_evaluation.policy_accumulation --run-directory "$C/policy-accumulation" > "$C/policy-accumulation.log" 2>&1; echo "exit $?"
    step numeric-path; guard
    rm -rf "$C/numeric-path"
    $PY -m experiments.pvldb_evaluation.verify_numeric_path --run-directory "$C/numeric-path" > "$C/numeric-path.log" 2>&1; echo "exit $?"
fi
if wanted faults; then
    step runtime-faults; guard
    rm -rf "$R/runtime-faults"
    $PY -m experiments.pvldb_evaluation.runtime_faults --run-directory "$R/runtime-faults" --unity-url $UNITY \
        --binary .runtime/dependencies/tn-llama/llama-server \
        --fault-binary .runtime/dependencies/tn-llama-fault/llama-server \
        --plain-binary .runtime/llama-build/plain-cuda/bin/llama-server \
        --model-path "$M" --sdk-build-record $SDK --port 18345 --gpu-layers 99 > "$R/runtime-faults.log" 2>&1
    tail -6 "$R/runtime-faults.log" | cut -c1-160
fi
if wanted decrypt; then
    step decrypt-reliability; guard
    rm -rf "$R/decrypt-reliability"
    $PY -m experiments.pvldb_evaluation.decrypt_reliability --run-directory "$R/decrypt-reliability" --unity-url $UNITY \
        --binary .runtime/dependencies/tn-llama/llama-server --model-path "$M" --sdk-build-record $SDK \
        --gpu-layers 99 --runs 50 > "$R/decrypt-reliability.log" 2>&1
    tail -3 "$R/decrypt-reliability.log" | cut -c1-160
fi
if wanted mutants; then
    step mutants; guard
    rm -rf "$R/mutants"
    baseline=$(ls -d "$R"/runtime-faults/control 2>/dev/null | head -1)
    $PY -m experiments.pvldb_evaluation.propagation_mutants --run-directory "$R/mutants" --unity-url $UNITY \
        --sdk-build-record $SDK ${baseline:+--model-baseline "$baseline"} > "$R/mutants.log" 2>&1
    echo "baseline ${baseline:-none}"; tail -3 "$R/mutants.log" | cut -c1-160
fi
if wanted context; then
    step context-sensitivity; guard
    rm -rf "$R/context-sensitivity"
    $PY -m experiments.pvldb_evaluation.context_sensitivity --run-directory "$R/context-sensitivity" --unity-url $UNITY \
        --binary .runtime/dependencies/tn-llama/llama-server --model-path "$M" --sdk-build-record $SDK \
        --gpu-layers 99 > "$R/context-sensitivity.log" 2>&1; echo "exit $?"
fi
if wanted publication; then
    step publication-size; guard
    rm -rf "$R/publication-size"
    $PY -m experiments.pvldb_evaluation.publication_size --run-directory "$R/publication-size" --unity-url $UNITY \
        --sdk-build-record $SDK --rows 100000 --sizes 256 512 1024 2048 4096 --repetitions 3 > "$R/publication-size.log" 2>&1
    tail -40 "$R/publication-size.log" | cut -c1-160
fi
if wanted performance; then
    step performance; guard
    rm -rf "$R/performance"
    $PY -m experiments.pvldb_evaluation.performance --profile config/performance.json \
        --run-directory "$R/performance" --unity-url $UNITY --opa .runtime/dependencies/opa \
        --binary .runtime/dependencies/tn-llama/llama-server \
        --plain-binary .runtime/llama-build/plain-cuda/bin/llama-server \
        --model-path "$M" --sdk-build-record $SDK --port 18325 > "$R/performance.log" 2>&1
    tail -3 "$R/performance.log" | cut -c1-160
    $PY -m experiments.pvldb_evaluation.study_summary "$R/performance" --output "$R/performance.json"; echo "summary $?"
fi
if wanted relation; then
    step relation; guard
    rm -rf "$R/relation-market" "$R/relation-tpch"
    $PY -m experiments.pvldb_evaluation.relation_study --run-directory "$R/relation-market" \
        --market-rows 1000 10000 100000 --scale-factors > "$R/relation-market.log" 2>&1; echo "market $?"
    $PY -m experiments.pvldb_evaluation.relation_study --run-directory "$R/relation-tpch" --market-rows \
        --scale-factors 0.001 0.01 --contributor-scale-limit 0.01 > "$R/relation-tpch.log" 2>&1; echo "tpch $?"
fi
step done
df -BG /mnt/c | tail -1
