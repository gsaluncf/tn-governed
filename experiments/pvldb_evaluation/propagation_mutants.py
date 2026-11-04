"""Mutation testing of governed propagation and its verifiers.

Producer mutants change one step of a live run so the endpoint's real keys sign
an incorrect output: a dropped policy, a rewritten claim, an omitted input.
Artifact mutants change retained evidence without those keys. Each mutant records
whether the running endpoint stopped it and whether the offline verifiers
rejected the retained evidence. A mutant that completes and verifies survives.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import traceback
from contextlib import contextmanager, redirect_stdout
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

import tn
from tn_governed.values.primitives import VALUE_TYPE, Context
from tn_governed.values.verify import verify

from . import frames
from .evidence_mutants import ARTIFACT_MUTANTS, MODEL_MUTANTS, ZERO, Mutant
from .run import run_case
from .verify_frame import verify_frame

ROWS = 4


@contextmanager
def wrapped(owner, name, replacement):
    original = getattr(owner, name)

    def call(self, *args, **kwargs):
        return replacement(original, self, *args, **kwargs)

    with patch.object(owner, name, call):
        yield


def publishing(operation, change):
    def replacement(original, self, data, **options):
        if options["request"].operation == operation:
            change(self, options)
        return original(self, data, **options)
    return lambda: wrapped(Context, "_publish", replacement)


def recording(kind, change, operation=None):
    def replacement(original, self, record_kind, request, call_id, details):
        if record_kind == kind and operation in (None, request.operation):
            details = change(self, deepcopy(details), request)
        return original(self, record_kind, request, call_id, details)
    return lambda: wrapped(Context, "_append", replacement)


def replaced(**fields):
    def change(_context, details, _request):
        return {**details, **fields}
    return change


def frame_facts(change):
    """Change the facts shared by the signed Result and the exported observation."""
    def apply(context, options):
        change(context._frame_pending[options["call_id"]])
    return publishing("dataframe_calculate", apply)


def release_without_gate(_original, self, data, request):
    use = tn.UseContext(self.application, self.purpose, request.operation)
    publication = self.session.release(data, use=use, to="governed-runtime",
                                       object_type=VALUE_TYPE, decide=lambda _: True)
    self._retain_publication(data, publication)
    return publication


def merge_first_input_only(_original, _self, _values, opened):
    return opened[0][0]


@contextmanager
def dropped_policy(gate_active):
    with wrapped(Context, "_merge_opened", merge_first_input_only):
        if gate_active:
            yield
        else:
            with wrapped(Context, "_release_value", release_without_gate):
                yield


def permissive_decision(_original, self, request, call_id):
    """Grant any request while a local rule would refuse it."""
    details = {"permitted": True, "requested_permit": True, "reason": "granted locally",
               "obligations": ["monitor"], "parameters": list(request.parameters),
               "discharged": [{"obligation": "monitor", "satisfied": True,
                               "evidence": self._monitor(request).evidence}],
               "policies": [{"authority": p.governed_by, "policy": p.policy_ref,
                             "revision": p.revision_id} for p in request.policies],
               "considered_claims": [c.id for c in request.claims], "claim_judgments": []}
    return self._append("Decision", request, call_id, details)


def public_disclosure(original, self, operation, values, **options):
    if operation == "reveal":
        options["destination"] = "public-web"
    return original(self, operation, values, **options)


@contextmanager
def disclosure_outside_grant():
    with wrapped(Context, "_decision", permissive_decision), \
            wrapped(Context, "perform", public_disclosure):
        yield


def launder_second_operand(original, self, operation, values, **options):
    """Application code reveals one operand and supplies it as an ordinary literal."""
    if operation == "concat" and len(values) == 2:
        literal = self.perform("reveal", values[1:], destination="internal-console")
        return original(self, operation, values[:1], destination=None,
                        parameters=(literal, "right"))
    return original(self, operation, values, **options)


def rewrite_cell(change):
    def replacement(original, self, cells, policy, **options):
        return original(self, tuple(change(c, s) for c, s in cells), policy, **options)
    return lambda: wrapped(Context, "originate_batch", replacement)


def swapped_source_policies(original, self, cells, policy, *, request, **options):
    others = [p for p in request.policies if not p.matches_contract(policy)]
    return original(self, cells, others[0] if others else policy, request=request, **options)


def drop_claims(_context, options):
    options["claims"] = []


def foreign_claim(_context, options):
    options["claims"] = [*options["claims"], options["decision_id"]]


def invented_claim(context, options):
    request, call_id = options["request"], options["call_id"]
    options["claims"] = [*options["claims"],
                         context._append("Claim", request, call_id, {"statement": "Invented."})]


def drop_input(_context, options):
    options["values"] = options["values"][:1]


def reverse_inputs(_context, options):
    options["values"] = options["values"][::-1]


def rewrite_origin_row(_context, options):
    options["origins"] = [{**options["origins"][0], "row": 99}, *options["origins"][1:]]


def clear_origins(_context, options):
    options["origins"] = []


def wrong_amount(_context, options):
    options["content"] = options["content"] + 1


def wrong_string(_context, options):
    options["content"] = options["content"] + "!"


def literal_claimant(_context, options):
    options["literals"] = [{"parameter_index": 0, "position": "right", "claims": ["invented"]}]


def first_policy_only(_context, details, _request):
    return {**details, "policies": details["policies"][:1]}


def no_discharge(_context, details, _request):
    return {**details, "obligations": [], "discharged": []}


def unbacked_discharge(_context, details, _request):
    return {**details, "discharged": [{**d, "evidence": ZERO} for d in details["discharged"]]}


def blank_statement(_context, details, _request):
    return {**details, "statement": " "}


def stale_decision(context, details, _request):
    decisions = context.recorder.ids()[:3]
    return {**details, "decision_id": decisions[0]}


def transition_without_claims(_context, details, _request):
    return {**details, "transition": {**details["transition"], "retained_claims": []}}


def duplicate_result(original, self, kind, request, call_id, details):
    identity = original(self, kind, request, call_id, details)
    if kind == "Result" and request.operation == "upper":
        return original(self, kind, request, call_id, details)
    return identity


def drop_opa_stage(facts):
    facts["opa_decisions"].pop()


def alter_opa_reason(facts):
    facts["opa_decisions"][0]["reason"] = "changed"


def drop_row_dependencies(facts):
    facts["row_selection_sources"] = []


def drop_output_lineage(facts):
    facts["output_columns"] = {"amount": []}


def drop_input_cell(facts):
    facts["source_cells"].pop()


PRODUCER_MUTANTS = (
    Mutant("claim_dropped_by_string_operation", "claim", publishing("upper", drop_claims)),
    Mutant("claim_dropped_by_aggregate", "claim", publishing("dataframe_calculate", drop_claims)),
    Mutant("claim_citation_names_other_record", "claim", publishing("upper", foreign_claim)),
    Mutant("claim_introduced_outside_attest", "claim", publishing("upper", invented_claim)),
    Mutant("claim_statement_blanked", "claim", recording("Claim", blank_statement)),
    Mutant("input_dropped_from_binding", "input", publishing("concat", drop_input)),
    Mutant("inputs_reversed_in_binding", "input", publishing("concat", reverse_inputs)),
    Mutant("origins_cleared", "input", publishing("upper", clear_origins)),
    Mutant("origin_row_rewritten", "input", publishing("upper", rewrite_origin_row)),
    Mutant("literal_given_claimant", "input", publishing("concat", literal_claimant)),
    Mutant("policy_dropped_with_release_gate", "policy", lambda: dropped_policy(True)),
    Mutant("policy_dropped_gate_bypassed", "policy", lambda: dropped_policy(False)),
    Mutant("source_published_under_other_policy", "policy",
           lambda: wrapped(Context, "originate_batch", swapped_source_policies)),
    Mutant("decision_omits_contract", "decision", recording("Decision", first_policy_only, "concat")),
    Mutant("decision_omits_claims", "decision",
           recording("Decision", replaced(considered_claims=[]), "upper")),
    Mutant("decision_omits_obligation", "decision", recording("Decision", no_discharge, "upper")),
    Mutant("decision_cites_unbacked_action", "decision", recording("Decision", unbacked_discharge, "upper")),
    Mutant("disclosure_outside_grant", "decision", disclosure_outside_grant),
    Mutant("result_field_commitment_changed", "result",
           recording("Result", replaced(field_commitment=ZERO), "upper")),
    Mutant("result_cites_other_decision", "result", recording("Result", stale_decision, "upper")),
    Mutant("result_transition_drops_claim", "result", recording("Result", transition_without_claims, "upper")),
    Mutant("result_recorded_twice", "result", lambda: wrapped(Context, "_append", duplicate_result)),
    Mutant("aggregate_value_wrong", "result", publishing("dataframe_calculate", wrong_amount)),
    Mutant("scalar_number_wrong", "result", publishing("add", wrong_amount)),
    Mutant("source_value_changed", "source",
           rewrite_cell(lambda c, s: (c + 1 if type(c) is int else c, s))),
    Mutant("source_snapshot_digest_changed", "source",
           rewrite_cell(lambda c, s: (c, {**s, "snapshot_sha256": "0" * 64}))),
    Mutant("source_row_ordinal_changed", "source",
           rewrite_cell(lambda c, s: (c, {**s, "row": s["row"] + 1000}))),
    Mutant("frame_plan_changed", "dataframe",
           lambda: patch.object(frames, "PLAN", (*frames.PLAN, {"operation": "unrecorded"}))),
    Mutant("frame_policy_decision_altered", "dataframe", frame_facts(alter_opa_reason)),
    Mutant("frame_policy_stage_dropped", "dataframe", frame_facts(drop_opa_stage)),
    Mutant("frame_row_dependency_dropped", "dataframe", frame_facts(drop_row_dependencies)),
    Mutant("frame_output_lineage_dropped", "dataframe", frame_facts(drop_output_lineage)),
    Mutant("frame_input_cell_dropped", "dataframe", frame_facts(drop_input_cell)),
    Mutant("value_laundered_through_reveal", "boundary",
           lambda: wrapped(Context, "perform", launder_second_operand)),
    Mutant("string_computation_wrong", "boundary", publishing("upper", wrong_string)),
)


def verifier_message(root):
    """Return the first offline rejection for retained evidence, or None."""
    (root / "frame-verification.json").unlink(missing_ok=True)
    try:
        with open_null() as null, redirect_stdout(null):
            verify(root)
            verify_frame(root)
    except Exception as exc:
        return f"{type(exc).__name__}: {str(exc)[:200]}"
    return None


def open_null():
    return Path(os.devnull).open("w", encoding="utf-8")


def workload_check(error):
    """Identify the evaluation's expected-value comparison, which is not a TN control."""
    return bool(error) and error.get("stage") == "console_disclosure" and error.get("type") == "RuntimeError"


def producer_verdict(mutant, root, settings):
    directory = root / mutant.name
    try:
        with mutant.install(), open_null() as null, redirect_stdout(null):
            summary = run_case(directory, "primitive", rows=ROWS, depth=1, model=False, **settings)
    except Exception as exc:
        return {"harness_error": traceback.format_exception_only(exc)[-1][:300]}
    verifier = verifier_message(directory)
    runtime = summary.get("error")
    stopped = runtime if not workload_check(runtime) else None
    return {"runtime_error": stopped, "workload_check": workload_check(runtime),
            "verifier_rejection": verifier, "survived": stopped is None and verifier is None}


def artifact_verdict(mutant, baseline, root):
    directory = root / mutant.name
    shutil.copytree(baseline, directory)
    mutant.install(directory)
    verifier = verifier_message(directory)
    return {"runtime_error": None, "workload_check": False, "verifier_rejection": verifier,
            "survived": verifier is None}


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
    root.mkdir(parents=True, exist_ok=True)
    settings = dict(unity_url=args.unity_url, storage="files", sql_batch_size=64,
                    sdk_build_record=args.sdk_build_record)
    with open_null() as null, redirect_stdout(null):
        control = run_case(root / "control", "primitive", rows=ROWS, depth=1, model=False, **settings)
    if not (control["completed"] and control["verified"]):
        raise SystemExit("the unmodified run must complete and verify")
    if args.model_baseline and verifier_message(args.model_baseline.resolve()) is not None:
        raise SystemExit("the unmodified model run must verify")
    results = {}
    mutants = [*PRODUCER_MUTANTS, *ARTIFACT_MUTANTS]
    mutants.extend(MODEL_MUTANTS if args.model_baseline else ())
    for mutant in mutants:
        if args.only and mutant.name not in args.only:
            continue
        if mutant in ARTIFACT_MUTANTS:
            verdict = artifact_verdict(mutant, root / "control", root)
        elif mutant in MODEL_MUTANTS:
            verdict = artifact_verdict(mutant, args.model_baseline.resolve(), root)
        else:
            verdict = producer_verdict(mutant, root, settings)
        results[mutant.name] = {"family": mutant.family, **verdict}
        print(mutant.name, json.dumps(verdict)[:220], flush=True)
    (root / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
