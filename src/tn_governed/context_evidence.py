"""Correlate local native admission logs with retained decision execution artifacts."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import asdict, dataclass

from tn.canonical import _canonical_bytes

CONTEXT_PROTOCOL = "tn.llama.governance-context.v1"
_DECISION_PHASES = {3: "section_selection", 4: "governed_action"}
_ARTIFACT_FIELDS = ("request_json_b64", "rendered_prompt_b64", "runnable_manifest_b64")
_ACTION_EVENTS = {
    "sections_selected",
    "governed_tool_executed",
    "tool_result_accepted",
    "output_emitted_and_read_back",
    "standalone_use_completed",
    "source_chain_committed",
}
_RUNTIME_ACTION_EVENTS = {
    "sections_selected_runtime",
    "governed_tool_executed_runtime",
    "tool_result_accepted_runtime",
}


@dataclass(frozen=True, slots=True)
class ContextEvidence:
    protocol: str
    verified: bool
    task_ids: tuple[int, ...] = ()
    phases: tuple[int, ...] = ()
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON field in retained context evidence")
        result[key] = value
    return result


def _json(raw):
    def invalid_constant(_):
        raise ValueError("non-finite JSON number in retained context evidence")

    return json.loads(raw, object_pairs_hook=_unique_object, parse_constant=invalid_constant)


def _facts(row):
    facts = _json(row.get("facts_json", "{}"))
    _require(isinstance(facts, dict), "audit facts must be an object")
    return facts


def _bytes(row, field):
    value = row.get(field)
    _require(isinstance(value, str) and bool(value), f"missing retained {field}")
    raw = base64.b64decode(value, validate=True)
    _require(bool(raw), f"empty retained {field}")
    return raw


def _digest(domain, raw):
    return "sha256:" + hashlib.sha256(domain.encode() + b"\0" + raw).hexdigest()


def _ordered(rows, label):
    sequence = [row.get("sequence") for row in rows]
    _require(
        all(type(value) is int and value >= 0 for value in sequence), f"missing {label} sequence"
    )
    _require(
        all(left < right for left, right in zip(sequence, sequence[1:], strict=False)),
        f"{label} records are duplicated or out of order",
    )


def _identity(row, run_id, request_digest, source_id):
    _require(
        row.get("run_id") == run_id
        and row.get("request_digest") == request_digest
        and row.get("target_row_hash") == source_id,
        "audit context belongs to another source, request, or run",
    )
    _require(row.get("outcome") == "allow", "context admission or execution was not allowed")


def _source(facts, source_id):
    values = [
        facts[key] for key in ("source_object_id", "source_row_hash") if facts.get(key) is not None
    ]
    _require(values == [source_id], "context source identity is missing or differs")


def _control(request, phase):
    controls = []
    for message in request.get("messages", []):
        content = message.get("content")
        if message.get("role") != "user" or not isinstance(content, str):
            continue
        try:
            value = _json(content)
        except (ValueError, TypeError):
            continue
        if (
            isinstance(value, dict)
            and value.get("phase") == _DECISION_PHASES[phase]
            and "applicable_source_governance" in value
        ):
            controls.append((content, value))
    _require(len(controls) == 1, "decision request lacks one exact governance context")
    content, value = controls[0]
    context = value["applicable_source_governance"]
    _require(isinstance(context, dict) and bool(context), "decision governance context is empty")
    return content, context


def _has_decision_context(trace):
    for row in trace:
        phase = row.get("phase")
        if phase not in _DECISION_PHASES or not row.get("request_json_b64"):
            continue
        try:
            _control(_json(_bytes(row, "request_json_b64")), phase)
        except (ValueError, TypeError, KeyError, AttributeError):
            continue
        return True
    return False


def _execution_key(row, facts):
    identity = facts.get("execution_identity")
    if isinstance(identity, dict) and identity.get("backend") == "vllm":
        _require(
            row.get("llama_task_id") is None and row.get("llama_slot_id") is None,
            "vLLM execution has conflicting llama task identity",
        )
        _require(
            all(
                identity.get(key) is not None
                for key in (
                    "engine_instance",
                    "request_id",
                    "external_request_id",
                    "client_index",
                    "destination",
                    "wave",
                )
            ),
            "vLLM execution identity is incomplete",
        )
        return _canonical_bytes(identity)
    task, slot = row.get("llama_task_id"), row.get("llama_slot_id")
    _require(
        type(task) is int and task >= 0 and type(slot) is int and slot >= 0,
        "decision task identity is missing",
    )
    return task, slot


def _check_artifacts(start, prepared, facts, source_id):
    body, prompt, raw_manifest = [_bytes(start, field) for field in _ARTIFACT_FIELDS]
    _require(
        all(_bytes(prepared, field) == _bytes(start, field) for field in _ARTIFACT_FIELDS),
        "execution artifacts differ from the prepared turn",
    )
    request, manifest = _json(body), _json(raw_manifest)
    _require(
        isinstance(request, dict) and isinstance(manifest, dict),
        "request and token manifest must be objects",
    )
    _require(body == _canonical_bytes(request), "model request is not the issued canonical JSON")
    content, context = _control(request, facts["phase"])
    if facts.get("source_object_id") is not None:
        _require(
            context.get("schema") == "tn.llama.decision-context.v1",
            "native object context has an unrecognized semantic schema",
        )
        sources = context.get("sources")
        _require(
            isinstance(sources, list) and all(isinstance(item, dict) for item in sources),
            "native context lacks attributed sources",
        )
        matching = [item for item in sources if item.get("object_id") == source_id]
        _require(
            len(matching) == 1
            and isinstance(matching[0].get("governance"), dict)
            and bool(matching[0]["governance"]),
            "native context semantics do not belong to the admitted source",
        )
    _require(content.encode() in prompt, "rendered prompt omits the decision governance content")
    _require(
        facts.get("context_digest") == _digest(CONTEXT_PROTOCOL, _canonical_bytes(context)),
        "decision governance context digest mismatch",
    )
    _require(
        facts.get("model_request_digest") == _digest("tn.llama.model-request.v1", body),
        "model request digest mismatch",
    )
    _require(
        facts.get("rendered_prompt_digest") == _digest("tn.llama.rendered-prompt.v1", prompt),
        "rendered prompt digest mismatch",
    )
    identity = facts.get("execution_identity")
    if isinstance(identity, dict) and identity.get("backend") == "vllm":
        domain = "tn.vllm.execution.v1"
        tokens = manifest.get("prompt_token_ids")
        _require(
            all(
                manifest.get(key) == identity[key]
                for key in ("engine_instance", "request_id", "external_request_id")
            ),
            "vLLM token manifest belongs to another execution",
        )
    else:
        domain = "tn.llama.runnable-task.v1"
        tokens = manifest.get("task", {}).get("tokens")
    _require(
        manifest.get("schema") == domain
        and isinstance(tokens, list)
        and bool(tokens)
        and all(type(token) is int for token in tokens),
        "missing actual prompt token manifest",
    )
    _require(
        facts.get("runnable_task_digest") == _digest(domain, _canonical_bytes(manifest)),
        "runnable token manifest digest mismatch",
    )
    # Source attribution and semantic verification are recorded by the native admission event.
    _source(facts, source_id)


def _check_completion(audit, trace, binding, *, run_id, source_id, expected_release):
    emitted = [row for row in audit if row.get("kind") == "output_emitted_and_read_back"]
    completed = [
        row for row in audit
        if row.get("kind") in {"standalone_use_completed", "source_chain_committed"}
    ]
    _require(
        len(emitted) == len(completed) == 1,
        "report completion requires one emission and one terminal audit event",
    )
    facts = _facts(binding)
    identity = _execution_key(binding, facts)
    native = facts.get("source_object_id") is not None
    _require(
        facts.get("phase") == 4
        and all(_execution_key(row, _facts(row)) == identity for row in (*emitted, *completed))
        and completed[0]["kind"] == (
            "standalone_use_completed" if native else "source_chain_committed"
        )
        and binding["sequence"] < emitted[0]["sequence"] < completed[0]["sequence"],
        "report completion is not bound to the last governed decision",
    )
    _require(
        not any(row.get("kind") == "terminal_error" for row in audit),
        "completed report evidence contains a terminal error",
    )
    releases = [row for row in trace if row.get("kind") == "release"]
    _require(len(releases) == 1, "report completion lacks one retained release")
    release = releases[0]
    _require(
        release is trace[-1]
        and release.get("run_id") == run_id
        and release.get("phase") == 4
        and release.get("task_id") == binding.get("llama_task_id")
        and release.get("slot_id") == binding.get("llama_slot_id"),
        "retained release is not the terminal result of the report inference",
    )
    payload = _json(_bytes(release, "parsed_content_b64"))
    source_field = "source_object_id" if native else "source_row_hash"
    output_field = "output_object_id" if native else "output_row_hash"
    _require(
        isinstance(payload, dict)
        and payload.get("protocol") == ("tn.llama.release.v2" if native else "tn.llama.release.v1")
        and payload.get("run_id") == run_id
        and payload.get(source_field) == source_id
        and isinstance(payload.get(output_field), str)
        and bool(payload[output_field]),
        "retained release does not identify the admitted source and output",
    )
    client_trace = payload.get("trace")
    _require(
        isinstance(client_trace, list) and all(isinstance(item, dict) for item in client_trace),
        "retained release lacks its execution trace",
    )
    _check_released_actions(audit, client_trace, source_id=source_id, native=native)
    readbacks = [item for item in client_trace if item.get("event") == "output_readback"]
    deliveries = [item for item in client_trace if item.get("event") == "release"]
    _require(
        len(readbacks) == len(deliveries) == 1
        and client_trace.index(readbacks[0]) < client_trace.index(deliveries[0])
        and deliveries[0] is client_trace[-1]
        and deliveries[0].get("state") == "complete"
        and all(
            item.get("task_id") == binding.get("llama_task_id")
            and item.get("slot_id") == binding.get("llama_slot_id")
            and item.get("row_hash") == payload[output_field]
            and item.get("event_id") == (
                payload[output_field] if native else payload.get("output_event_id")
            )
            for item in (*readbacks, *deliveries)
        ),
        "release trace does not bind the output publication to the report inference",
    )
    if expected_release is not None:
        _require(
            isinstance(expected_release, dict)
            and _canonical_bytes(payload) == _canonical_bytes(expected_release),
            "retained release differs from the received report publication",
        )


def _check_released_actions(audit, client_trace, *, source_id, native):
    _ordered([{"sequence": item.get("ordinal")} for item in client_trace], "release trace")
    action_kinds = {
        "sections_selected": "sections_selected",
        "sections_selected_runtime": "sections_selected_runtime",
        "tool_executed": "governed_tool_executed",
        "tool_executed_runtime": "governed_tool_executed_runtime",
    }
    actions = [item for item in client_trace if item.get("event") in action_kinds]
    recorded = [row for row in audit if row.get("kind") in action_kinds.values()]
    _require(
        len(actions) == len(recorded),
        "release action history differs from the retained audit history",
    )
    for item, row in zip(actions, recorded, strict=True):
        _require(
            action_kinds[item["event"]] == row["kind"]
            and item.get("task_id") == row.get("llama_task_id")
            and item.get("slot_id") == row.get("llama_slot_id")
            and item.get("state") == "governed_action",
            "release action differs from its authorized audit execution",
        )
        if item["event"].startswith("sections_selected"):
            _require(
                item.get("row_hash") == source_id,
                "release selection belongs to another admitted source",
            )
    tools = [item for item in actions if item["event"].startswith("tool_executed")]
    receipts = [item for item in client_trace if item.get("event") == "receipt_inserted"]
    _require(len(tools) == len(receipts), "release tool history lacks exact inserted receipts")
    for index, (tool, receipt) in enumerate(zip(tools, receipts, strict=True)):
        next_tool = tools[index + 1]["ordinal"] if index + 1 < len(tools) else float("inf")
        _require(
            tool["ordinal"] < receipt["ordinal"] < next_tool
            and all(isinstance(tool.get(key), str) and tool[key]
                    for key in ("tool_name", "event_id", "row_hash"))
            and all(receipt.get(key) == tool.get(key) for key in (
                "task_id", "slot_id", "tool_name", "event_id", "row_hash", "selected_sections",
            )),
            "release receipt is not bound to its tool execution",
        )
    if native:
        executed = [row for row in audit if row.get("kind") == "governed_tool_executed"]
        accepted = [row for row in audit if row.get("kind") == "tool_result_accepted"]
        _require(len(executed) == len(accepted), "native tool history lacks accepted results")
        for execution, acceptance in zip(executed, accepted, strict=True):
            facts, accepted_facts = _facts(execution), _facts(acceptance)
            _require(
                execution["sequence"] < acceptance["sequence"]
                and _execution_key(execution, facts) == _execution_key(acceptance, accepted_facts)
                and facts.get("content_digest") == accepted_facts.get("content_digest"),
                "native tool result differs from its executed action",
            )


def _check_runtime_actions(audit, admission, bound, *, run_id, request_digest, source_id):
    runtime = [row for row in audit if row.get("kind") in _RUNTIME_ACTION_EVENTS]
    selection = [row for row in runtime if row["kind"] == "sections_selected_runtime"]
    _require(len(selection) <= 1, "runtime section selection is duplicated")
    if selection:
        _require(
            selection[0]["sequence"] < bound[0]["sequence"],
            "runtime selection must precede model decisions",
        )
    emitted = [row for row in audit if row.get("kind") == "output_emitted_and_read_back"]
    for row in runtime:
        _identity(row, run_id, request_digest, source_id)
        facts = _facts(row)
        _require(
            row.get("llama_task_id") is None and row.get("llama_slot_id") is None
            and all(facts.get(key) is None for key in (
                "phase", "turn_ordinal", "execution_identity", "model_request_digest",
                "rendered_prompt_digest", "runnable_task_digest", "context_digest",
            )),
            "runtime action is incorrectly assigned to model inference",
        )
        _require(
            admission["sequence"] < row["sequence"]
            and all(row["sequence"] < item["sequence"] for item in emitted),
            "runtime action is outside the admitted computation",
        )
    tools = [row for row in runtime if row["kind"] != "sections_selected_runtime"]
    _require(len(tools) % 2 == 0, "runtime tool execution lacks its accepted result")
    for executed, accepted in zip(tools[::2], tools[1::2], strict=True):
        digest = _facts(executed).get("content_digest")
        _require(
            executed["kind"] == "governed_tool_executed_runtime"
            and accepted["kind"] == "tool_result_accepted_runtime"
            and isinstance(digest, str) and bool(digest)
            and _facts(accepted).get("content_digest") == digest,
            "runtime tool result is not bound to its execution",
        )
    return bool(selection)


def _check_context(audit, trace, *, run_id, request_digest, source_id, expected_release):
    _require(
        all(isinstance(value, str) and value for value in (run_id, request_digest, source_id)),
        "expected source, request, and run identities are required",
    )
    _ordered(audit, "audit")
    _ordered(trace, "trace")
    admissions = [row for row in audit if row.get("kind") == "governance_opened_and_verified"]
    bound = [row for row in audit if row.get("kind") == "governance_context_bound"]
    authorized = [row for row in audit if row.get("kind") == "turn_begin_authorized"]
    _require(len(admissions) == 1, "expected one native governance admission")
    admission = admissions[0]
    _identity(admission, run_id, request_digest, source_id)
    admission_facts = _facts(admission)
    _source(admission_facts, source_id)
    _require(
        admission_facts.get("governance_context_protocol") == CONTEXT_PROTOCOL
        and admission_facts.get("hashes_verified") is True,
        "native admission did not verify the governance-context protocol",
    )
    count = admission_facts.get("governance_value_count")
    _require(
        type(count) is int
        and count > 0
        and count == admission_facts.get("governance_commitment_count"),
        "native admission lacks complete verified governance commitments",
    )
    _require(
        admission.get("llama_task_id") is None and admission_facts.get("phase") is None,
        "native admission is incorrectly assigned to a model turn",
    )
    _require(
        len(bound) == len(authorized) and bool(bound),
        "each decision needs one context binding and execution authorization",
    )
    runtime_selected = _check_runtime_actions(
        audit, admission, bound, run_id=run_id, request_digest=request_digest, source_id=source_id,
    )
    executions = [
        row for row in trace if row.get("kind") in {"turn_prepared", "turn_started", "model_result"}
    ]
    _require(len(executions) == 3 * len(bound), "incomplete or extra decision execution traces")
    _require(
        not any(row.get("kind") == "commitments_matched" for row in audit),
        "governance-context evidence contains a model echo assertion",
    )
    task_ids, phases, seen = [], [], set()
    executions_by_identity = {}
    previous_authorization = admission["sequence"]
    for index, (binding, begin) in enumerate(zip(bound, authorized, strict=True)):
        for row in (binding, begin):
            _identity(row, run_id, request_digest, source_id)
        facts, begin_facts = _facts(binding), _facts(begin)
        phase = facts.get("phase")
        _require(
            phase == (3 if index == 0 and not runtime_selected else 4),
            "selection must precede every governed action",
        )
        identity = _execution_key(binding, facts)
        _require(
            identity == _execution_key(begin, begin_facts) and identity not in seen,
            "decision authorization has a mismatched or reused task identity",
        )
        seen.add(identity)
        _require(
            previous_authorization < binding["sequence"] < begin["sequence"],
            "context was not bound after admission and before execution authorization",
        )
        previous_authorization = begin["sequence"]
        next_binding = bound[index + 1]["sequence"] if index + 1 < len(bound) else float("inf")
        executions_by_identity[identity] = (begin["sequence"], next_binding, facts)
        for field in (
            "phase",
            "turn_ordinal",
            "model_request_digest",
            "rendered_prompt_digest",
            "runnable_task_digest",
        ):
            _require(
                facts.get(field) is not None and facts[field] == begin_facts.get(field),
                "context binding and execution authorization differ",
            )
        prepared, start, result = executions[index * 3 : index * 3 + 3]
        _require(
            [row.get("kind") for row in (prepared, start, result)]
            == ["turn_prepared", "turn_started", "model_result"],
            "model execution stages are out of order",
        )
        _require(
            all(
                row.get("run_id") == run_id and row.get("phase") == phase
                for row in (prepared, start, result)
            ),
            "trace run or phase identity differs",
        )
        _require(
            prepared.get("task_id") is None and prepared.get("slot_id") is None,
            "prepared turn already has a task identity",
        )
        for row in (start, result):
            _require(
                row.get("task_id") == binding.get("llama_task_id")
                and row.get("slot_id") == binding.get("llama_slot_id"),
                "execution trace task identity differs from authorization",
            )
        _bytes(result, "raw_model_output_b64")
        _check_artifacts(start, prepared, facts, source_id)
        if binding.get("llama_task_id") is not None:
            task_ids.append(binding["llama_task_id"])
        phases.append(phase)
    for row in audit:
        if row.get("kind") not in _ACTION_EVENTS:
            continue
        facts = _facts(row)
        _require(facts.get("phase") in _DECISION_PHASES, "action execution lacks a decision phase")
        _identity(row, run_id, request_digest, source_id)
        identity = _execution_key(row, facts)
        _require(
            identity in executions_by_identity, "executed action lacks its bound decision turn"
        )
        lower, upper, bound_facts = executions_by_identity[identity]
        _require(
            lower < row["sequence"] < upper,
            "action execution is outside its authorized decision turn",
        )
        for field in (
            "phase",
            "turn_ordinal",
            "model_request_digest",
            "rendered_prompt_digest",
            "runnable_task_digest",
        ):
            _require(
                facts.get(field) == bound_facts.get(field),
                "action execution differs from its governance context binding",
            )
    _check_completion(
        audit, trace, bound[-1], run_id=run_id, source_id=source_id,
        expected_release=expected_release,
    )
    return tuple(task_ids), tuple(phases)


def inspect_governance_context(
    audit, trace, *, run_id, request_digest, source_id, expected_release=None,
):
    """Inspect complete local execution evidence, optionally bound to a received release."""
    protocol = "unrecognized"
    try:
        admissions = [row for row in audit if row.get("kind") == "governance_opened_and_verified"]
        uses_context = (
            any(row.get("kind") == "governance_context_bound" for row in audit)
            or any(_facts(row).get("governance_context_protocol") is not None for row in admissions)
            or _has_decision_context(trace)
        )
        if uses_context:
            protocol = CONTEXT_PROTOCOL
            task_ids, phases = _check_context(
                audit, trace, run_id=run_id, request_digest=request_digest, source_id=source_id,
                expected_release=expected_release,
            )
            return ContextEvidence(protocol, True, task_ids, phases)
        echoes = [row for row in audit if row.get("kind") == "commitments_matched"]
        _require(len(admissions) == len(echoes) == 1, "no recognized governance evidence protocol")
        protocol = "legacy_echo"
        admission, echo = admissions[0], echoes[0]
        for row in (admission, echo):
            _identity(row, run_id, request_digest, source_id)
        opening, match = _facts(admission), _facts(echo)
        _require(
            audit.index(admission) < audit.index(echo)
            and opening.get("hashes_verified") is True
            and match.get("hashes_matched") is True,
            "historical governance opening and commitment echo are not verified",
        )
        count = opening.get("governance_commitment_count")
        _require(
            type(count) is int and count > 0 and count == match.get("governance_commitment_count"),
            "historical governance commitment counts differ",
        )
        return ContextEvidence(protocol, True)
    except (ValueError, KeyError, TypeError, AttributeError, binascii.Error) as error:
        return ContextEvidence(protocol, False, errors=(str(error),))
