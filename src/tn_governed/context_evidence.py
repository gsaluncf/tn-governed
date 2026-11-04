"""Correlate local native admission logs with retained decision execution artifacts."""

from __future__ import annotations

import binascii
from dataclasses import asdict, dataclass

from .context_artifacts import (
    CONTEXT_PROTOCOL,
    DECISION_PHASES,
    audit_facts,
    check_artifacts,
    check_decrypt_turn,
    check_identity,
    check_ordered,
    check_source,
    execution_key,
    has_decision_context,
    require,
    retained_bytes,
)
from .context_completion import check_completion, check_runtime_actions

_ACTION_EVENTS = {
    "sections_selected",
    "governed_tool_executed",
    "tool_result_accepted",
    "output_emitted_and_read_back",
    "standalone_use_completed",
    "source_chain_committed",
}
_EXECUTION_STAGES = ("turn_prepared", "turn_started", "model_result")
_TURN_FIELDS = ("phase", "turn_ordinal", "model_request_digest", "rendered_prompt_digest", "runnable_task_digest")


@dataclass(frozen=True, slots=True)
class ContextEvidence:
    protocol: str
    verified: bool
    task_ids: tuple[int, ...] = ()
    phases: tuple[int, ...] = ()
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _check_context(
    audit, trace, *, run_id, request_digest, source_id, expected_release, source_envelope,
    governance_hash_key=None,
):
    expected = (run_id, request_digest, source_id)
    require(all(isinstance(value, str) and value for value in expected),
            "expected source, request, and run identities are required")
    check_ordered(audit, "audit")
    check_ordered(trace, "trace")
    admission = _check_admission(audit, *expected)
    bound = [row for row in audit if row.get("kind") == "governance_context_bound"]
    authorized = [row for row in audit if row.get("kind") == "turn_begin_authorized"]
    require(len(bound) == len(authorized) and bool(bound),
            "each decision needs one context binding and execution authorization")
    check_runtime_actions(audit, admission, run_id=run_id, request_digest=request_digest, source_id=source_id)
    executions = [row for row in trace if row.get("kind") in _EXECUTION_STAGES]
    require(len(executions) == 3 * len(bound), "incomplete or extra decision execution traces")
    require(not any(row.get("kind") == "commitments_matched" for row in audit),
            "governance-context evidence contains a model echo assertion")
    turns, windows = _check_turns(bound, authorized, executions, admission, expected)
    _check_actions(audit, windows, expected)
    # Values open only through the model's own decrypt call (LLM rule 9).
    check_decrypt_turn(turns, source_envelope, governance_hash_key)
    check_completion(audit, trace, bound[-1], run_id=run_id, source_id=source_id,
                     expected_release=expected_release)
    return (tuple(task for *_, task in turns if task is not None), tuple(phase for phase, *_ in turns))


def _check_admission(audit, run_id, request_digest, source_id):
    """The one native admission verified the governance-context protocol and every commitment."""
    admissions = [row for row in audit if row.get("kind") == "governance_opened_and_verified"]
    require(len(admissions) == 1, "expected one native governance admission")
    admission = admissions[0]
    check_identity(admission, run_id, request_digest, source_id)
    facts = audit_facts(admission)
    check_source(facts, source_id)
    require(facts.get("governance_context_protocol") == CONTEXT_PROTOCOL and facts.get("hashes_verified") is True,
            "native admission did not verify the governance-context protocol")
    count = facts.get("governance_value_count")
    require(type(count) is int and count > 0 and count == facts.get("governance_commitment_count"),
            "native admission lacks complete verified governance commitments")
    require(admission.get("llama_task_id") is None and facts.get("phase") is None,
            "native admission is incorrectly assigned to a model turn")
    return admission


def _check_turns(bound, authorized, executions, admission, expected):
    """Each decision is bound after admission, authorized, and executed in order.

    Return each turn as (phase, start, result, task) and each execution's sequence window.
    """
    turns, windows, previous = [], {}, admission["sequence"]
    for index, (binding, begin) in enumerate(zip(bound, authorized, strict=True)):
        facts = _check_turn_binding(binding, begin, index == 0, previous, windows, expected)
        previous = begin["sequence"]
        next_binding = bound[index + 1]["sequence"] if index + 1 < len(bound) else float("inf")
        windows[execution_key(binding, facts)] = (begin["sequence"], next_binding, facts)
        prepared, start, result = executions[index * 3 : index * 3 + 3]
        _check_turn_execution(binding, facts, prepared, start, result, expected)
        turns.append((facts["phase"], start, result, binding.get("llama_task_id")))
    return turns, windows


def _check_turn_binding(binding, begin, first_turn, previous, seen, expected):
    """A context binding and its execution authorization agree and name an unused execution."""
    for row in (binding, begin):
        check_identity(row, *expected)
    facts, begin_facts = audit_facts(binding), audit_facts(begin)
    require(facts.get("phase") == (3 if first_turn else 4), "the decrypt turn must precede every governed action")
    identity = execution_key(binding, facts)
    require(identity == execution_key(begin, begin_facts) and identity not in seen,
            "decision authorization has a mismatched or reused task identity")
    require(previous < binding["sequence"] < begin["sequence"],
            "context was not bound after admission and before execution authorization")
    for field in _TURN_FIELDS:
        require(facts.get(field) is not None and facts[field] == begin_facts.get(field),
                "context binding and execution authorization differ")
    return facts


def _check_turn_execution(binding, facts, prepared, start, result, expected):
    """The prepared, started, and result stages of one decision run in order under its identity."""
    run_id, _, source_id = expected
    stages = (prepared, start, result)
    require([row.get("kind") for row in stages] == list(_EXECUTION_STAGES), "model execution stages are out of order")
    require(all(row.get("run_id") == run_id and row.get("phase") == facts["phase"] for row in stages),
            "trace run or phase identity differs")
    require(prepared.get("task_id") is None and prepared.get("slot_id") is None,
            "prepared turn already has a task identity")
    for row in (start, result):
        require(row.get("task_id") == binding.get("llama_task_id") and row.get("slot_id") == binding.get("llama_slot_id"),
                "execution trace task identity differs from authorization")
    retained_bytes(result, "raw_model_output_b64")
    check_artifacts(start, prepared, facts, source_id)


def _check_actions(audit, windows, expected):
    """Each executed action ran inside its authorized decision turn, under that turn's binding."""
    for row in audit:
        if row.get("kind") not in _ACTION_EVENTS:
            continue
        facts = audit_facts(row)
        require(facts.get("phase") in DECISION_PHASES, "action execution lacks a decision phase")
        check_identity(row, *expected)
        identity = execution_key(row, facts)
        require(identity in windows, "executed action lacks its bound decision turn")
        lower, upper, bound_facts = windows[identity]
        require(lower < row["sequence"] < upper, "action execution is outside its authorized decision turn")
        for field in _TURN_FIELDS:
            require(facts.get(field) == bound_facts.get(field),
                    "action execution differs from its governance context binding")


def inspect_governance_context(
    audit, trace, *, run_id, request_digest, source_id, expected_release=None,
    source_envelope=None, governance_hash_key=None,
):
    """Inspect complete local execution evidence, optionally bound to a received release."""
    protocol = "unrecognized"
    try:
        admissions = [row for row in audit if row.get("kind") == "governance_opened_and_verified"]
        echoed = any(row.get("kind") == "commitments_matched" for row in audit)
        uses_context = (
            any(row.get("kind") == "governance_context_bound" for row in audit)
            or any(audit_facts(row).get("governance_context_protocol") is not None for row in admissions)
            or has_decision_context(trace)
        )
        if uses_context:
            protocol = CONTEXT_PROTOCOL
            task_ids, phases = _check_context(
                audit, trace, run_id=run_id, request_digest=request_digest, source_id=source_id,
                expected_release=expected_release, source_envelope=source_envelope,
                governance_hash_key=governance_hash_key,
            )
            return ContextEvidence(protocol, True, task_ids, phases)
        raise ValueError("a commitment echo proves nothing" if echoed
                         else "no recognized governance evidence protocol")
    except (ValueError, KeyError, TypeError, AttributeError, binascii.Error) as error:
        return ContextEvidence(protocol, False, errors=(str(error),))
