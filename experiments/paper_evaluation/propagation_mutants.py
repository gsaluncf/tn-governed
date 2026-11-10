"""Inject faults in signed policy, claim and action material on a small governed workload."""

from __future__ import annotations

import argparse
import json
import os
import shutil
from contextlib import contextmanager, redirect_stdout
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

import tn

from tn_governed.values.evidence import EvidenceError
from tn_governed.values.manifests import POLICY_SCHEMA
from tn_governed.values.primitives import Context
from tn_governed.values.verify import verify

from .evidence_mutants import ARTIFACT_MUTANTS, MODEL_MUTANTS, ZERO, Mutant
from .frames import DataframeGovernance
from .run import run_case
from .verify_frame import verify_frame

ROWS = 4


@contextmanager
def require_monitoring():
    """The signed source assignments explicitly require the receipts under test."""
    publish = DataframeGovernance.publish_assignment

    def monitored(owner, directory, *, columns, **kwargs):
        columns = deepcopy(columns)
        for column in columns.values():
            obligations = column["rule"].setdefault("obligations", [])
            if "monitor" not in obligations:
                obligations.append("monitor")
        return publish(owner, directory, columns=columns, **kwargs)

    with patch.object(DataframeGovernance, "publish_assignment", monitored):
        yield


@contextmanager
def changed_binding(operation, alter):
    """Change the actual field manifest immediately before the trusted writer signs it."""
    applied = []
    publish = Context._publish_policy
    set_group = tn.DataObject.set

    def publishing(ctx, data, field, declared, request, metadata, claims, actions):
        def writing(obj, key, value, *, group=None):
            if (obj is data and group == "evidence" and key is None
                    and value.get("manifest", {}).get("schema") == POLICY_SCHEMA):
                edited = deepcopy(value)
                alter(edited["manifest"]["bindings"][field], ctx)
                if edited != value:
                    applied.append(request.operation)
                    value = edited
            return set_group(obj, key, value, group=group)

        if request.operation != operation:
            return publish(ctx, data, field, declared, request, metadata, claims, actions)
        with patch.object(tn.DataObject, "set", writing):
            return publish(ctx, data, field, declared, request, metadata, claims, actions)

    with patch.object(Context, "_publish_policy", publishing):
        yield applied


def drop_claims(binding, _context):
    binding["claims"] = []


def substitute_claim(binding, _context):
    binding["claims"] = [binding["actions"][-1]]


def substitute_action(binding, _context):
    binding["actions"] = [*binding["actions"][:-1], binding["claims"][0]]


@contextmanager
def omitted_policy():
    """Publish the aggregate with the first source's policies while the real gate checks both."""
    applied = []
    publish = Context.publish_value

    def publishing(ctx, content, *, request, metadata, **kwargs):
        if request.operation == "dataframe_calculate" and len(request.policies) > len(metadata[0][0].policies):
            metadata = metadata[:1]
            applied.append(request.operation)
        return publish(ctx, content, request=request, metadata=metadata, **kwargs)

    with patch.object(Context, "publish_value", publishing):
        yield applied


@contextmanager
def unbacked_action():
    """Keep the required action but replace its signed receipt locator."""
    applied = []
    append = Context._append

    def recording(ctx, kind, request, call_id, details):
        if kind == "Decision" and request.operation == "dataframe_calculate" and details.get("discharged"):
            details = {**details, "discharged": [
                {**step, "evidence": ZERO} for step in details["discharged"]]}
            applied.append(request.operation)
        return append(ctx, kind, request, call_id, details)

    with patch.object(Context, "_append", recording):
        yield applied


PRODUCER_MUTANTS = (
    Mutant("claim_dropped_by_aggregate", "claim", lambda: changed_binding("dataframe_calculate", drop_claims)),
    Mutant("claim_citation_names_other_record", "claim", lambda: changed_binding("upper", substitute_claim)),
    Mutant("action_citation_names_claim", "action", lambda: changed_binding("dataframe_calculate", substitute_action)),
    Mutant("decision_cites_unbacked_action", "action", unbacked_action),
    Mutant("policy_dropped_with_release_gate", "policy", omitted_policy),
)


def verifier_message(root):
    """Recheck this disposable case, retaining the first verification rejection."""
    (root / "frame-verification.json").unlink(missing_ok=True)
    try:
        with open_null() as null, redirect_stdout(null):
            verify(root)
            verify_frame(root)
    except (EvidenceError, tn.governed.GovernedError, FileNotFoundError, ValueError) as exc:
        return f"{type(exc).__name__}: {str(exc)[:200]}"
    return None


def open_null():
    return Path(os.devnull).open("w", encoding="utf-8")


def workload_check(error):
    """Identify the evaluation's expected-value comparison, which is not a TN control."""
    return bool(error) and error.get("stage") == "console_disclosure" and error.get("type") == "RuntimeError"


def producer_verdict(mutant, root, settings):
    directory = root / mutant.name
    with mutant.install() as applied, open_null() as null, redirect_stdout(null):
        summary = run_case(directory, "primitive", rows=ROWS, depth=1, model=False, **settings)
    runtime = summary.get("error")
    if not applied:
        return {"harness_error": "mutation did not execute", "case_error": runtime}
    if runtime:
        if workload_check(runtime):
            return {"workload_check": runtime, "survived": True}
        if runtime["type"] not in {"EvidenceError", "OperationDenied", "UseDenied", "FileNotFoundError",
                                   "VerificationError"}:
            return {"harness_error": "unexpected execution failure", "case_error": runtime}
        return {"runtime_error": runtime, "survived": False}
    verifier = verifier_message(directory)
    if verifier:
        return {"verifier_rejection": verifier, "survived": False}
    # The workload independently checks the governed outputs against its known
    # source attestation. Keep that separate from runtime and wire verification.
    if not summary["verified"]:
        check = summary.get("verification_error")
        if check and check["type"] == "RuntimeError":
            return {"workload_check": check, "survived": True}
        return {"harness_error": "case did not complete verification", "case_error": check}
    return {"survived": True}


def artifact_verdict(mutant, baseline, root):
    directory = root / mutant.name
    shutil.copytree(baseline, directory)
    mutant.install(directory)
    verifier = verifier_message(directory)
    return {"verifier_rejection": verifier, "survived": verifier is None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-directory", type=Path, required=True)
    parser.add_argument("--unity-url", default="http://127.0.0.1:18080")
    parser.add_argument("--sdk-build-record", type=Path)
    parser.add_argument("--model-baseline", type=Path,
                        help="A completed model run directory for the model evidence family")
    parser.add_argument("--only", nargs="*")
    args = parser.parse_args()
    root = args.run_directory.resolve()
    root.mkdir(parents=True, exist_ok=False)
    settings = dict(unity_url=args.unity_url, storage="files", sql_batch_size=64,
                    sdk_build_record=args.sdk_build_record)
    with require_monitoring(), open_null() as null, redirect_stdout(null):
        control = run_case(root / "control", "primitive", rows=ROWS, depth=1, model=False, **settings)
    if not (control["completed"] and control["verified"]):
        raise SystemExit("the unmodified run must complete and verify")
    model_control = None
    if args.model_baseline:
        model_control = root / "model-control"
        shutil.copytree(args.model_baseline.resolve(), model_control)
        if verifier_message(model_control) is not None:
            raise SystemExit("the unmodified model run must verify")
    results = {}
    mutants = [*PRODUCER_MUTANTS, *ARTIFACT_MUTANTS]
    mutants.extend(MODEL_MUTANTS if args.model_baseline else ())
    if args.only and set(args.only) - {mutant.name for mutant in mutants}:
        parser.error("unknown or unavailable mutation in --only")
    for mutant in mutants:
        if args.only and mutant.name not in args.only:
            continue
        try:
            if mutant in ARTIFACT_MUTANTS:
                verdict = artifact_verdict(mutant, root / "control", root)
            elif mutant in MODEL_MUTANTS:
                verdict = artifact_verdict(mutant, model_control, root)
            else:
                with require_monitoring():
                    verdict = producer_verdict(mutant, root, settings)
        except Exception as exc:
            verdict = {"harness_error": f"{type(exc).__name__}: {str(exc)[:200]}"}
        results[mutant.name] = {"family": mutant.family, **verdict}
        print(mutant.name, json.dumps(verdict)[:220], flush=True)
    (root / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    return int(any("harness_error" in verdict for verdict in results.values()))


if __name__ == "__main__":
    raise SystemExit(main())
