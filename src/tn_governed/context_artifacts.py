"""Decode and check the retained artifacts of each model turn: what the model was sent and generated.

Every check reads retained bytes the runtime recorded. The decision request, its rendered
prompt, and its token manifest must match their audit digests; a decrypt turn must show the
governance before the model generates the one call that presents the signed hash keys.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re

from tn.canonical import _canonical_bytes

CONTEXT_PROTOCOL = "tn.llama.governance-context.v1"
DECISION_PHASES = {3: {"section_selection", "decrypt"}, 4: {"governed_action"}}
_ARTIFACT_FIELDS = ("request_json_b64", "rendered_prompt_b64", "runnable_manifest_b64")
_DECRYPT_TOOL = "decrypt_value"
_DECRYPT_CONTROL = {"phase", "user_request", "encrypted_data", "governance_hash",
                    "applicable_source_governance", "output_instruction"}
_ENCRYPTED_FIELD = {"group", "field", "data_hash"}
_VLLM_IDENTITY = ("engine_instance", "request_id", "external_request_id", "client_index", "destination", "wave")
# The backend decodes one tool call from this markup; reasoning, if any, is not content.
_TOOL_CALL = re.compile(r"\s*(?:<think>.*?</think>\s*)?<tool_call>(.*)</tool_call>\s*", re.DOTALL)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field in retained context evidence")
        result[key] = value
    return result


def parse_json(raw):
    """Strict JSON: a duplicate field or a non-finite number is refused."""
    def invalid_constant(_):
        raise ValueError("non-finite JSON number in retained context evidence")

    return json.loads(raw, object_pairs_hook=_unique_object, parse_constant=invalid_constant)


def audit_facts(row):
    facts = parse_json(row.get("facts_json", "{}"))
    require(isinstance(facts, dict), "audit facts must be an object")
    return facts


def retained_bytes(row, field):
    value = row.get(field)
    require(isinstance(value, str) and bool(value), f"missing retained {field}")
    raw = base64.b64decode(value, validate=True)
    require(bool(raw), f"empty retained {field}")
    return raw


def domain_digest(domain, raw):
    return "sha256:" + hashlib.sha256(domain.encode() + b"\0" + raw).hexdigest()


def check_ordered(rows, label):
    sequence = [row.get("sequence") for row in rows]
    require(all(type(value) is int and value >= 0 for value in sequence), f"missing {label} sequence")
    require(all(left < right for left, right in zip(sequence, sequence[1:], strict=False)),
            f"{label} records are duplicated or out of order")


def check_identity(row, run_id, request_digest, source_id):
    require(
        row.get("run_id") == run_id
        and row.get("request_digest") == request_digest
        and row.get("target_row_hash") == source_id,
        "audit context belongs to another source, request, or run",
    )
    require(row.get("outcome") == "allow", "context admission or execution was not allowed")


def check_source(facts, source_id):
    require(facts.get("source_object_id") == source_id, "context source identity is missing or differs")


def execution_key(row, facts):
    """The backend's identity of one model execution: a vLLM request, or a llama task and slot."""
    identity = facts.get("execution_identity")
    if isinstance(identity, dict) and identity.get("backend") == "vllm":
        require(row.get("llama_task_id") is None and row.get("llama_slot_id") is None,
                "vLLM execution has conflicting llama task identity")
        require(all(identity.get(key) is not None for key in _VLLM_IDENTITY),
                "vLLM execution identity is incomplete")
        return _canonical_bytes(identity)
    task, slot = row.get("llama_task_id"), row.get("llama_slot_id")
    require(type(task) is int and task >= 0 and type(slot) is int and slot >= 0,
            "decision task identity is missing")
    return task, slot


def _control_message(request, phase):
    controls = []
    for message in request.get("messages", []):
        content = message.get("content")
        if message.get("role") != "user" or not isinstance(content, str):
            continue
        try:
            value = parse_json(content)
        except (ValueError, TypeError):
            continue
        if (isinstance(value, dict) and value.get("phase") in DECISION_PHASES[phase]
                and "applicable_source_governance" in value):
            controls.append((content, value))
    require(len(controls) == 1, "decision request lacks one exact governance context")
    return controls[0]


def _control(request, phase):
    content, value = _control_message(request, phase)
    context = value["applicable_source_governance"]
    require(isinstance(context, dict) and bool(context), "decision governance context is empty")
    return content, context


def has_decision_context(trace):
    for row in trace:
        phase = row.get("phase")
        if phase not in DECISION_PHASES or not row.get("request_json_b64"):
            continue
        try:
            _control(parse_json(retained_bytes(row, "request_json_b64")), phase)
        except (ValueError, TypeError, KeyError, AttributeError):
            continue
        return True
    return False


def check_artifacts(start, prepared, facts, source_id):
    """The started turn's request, prompt, and token manifest are the bound ones, byte for byte."""
    body, prompt, raw_manifest = [retained_bytes(start, field) for field in _ARTIFACT_FIELDS]
    require(all(retained_bytes(prepared, field) == retained_bytes(start, field) for field in _ARTIFACT_FIELDS),
            "execution artifacts differ from the prepared turn")
    request, manifest = parse_json(body), parse_json(raw_manifest)
    require(isinstance(request, dict) and isinstance(manifest, dict), "request and token manifest must be objects")
    require(body == _canonical_bytes(request), "model request is not the issued canonical JSON")
    content, context = _control(request, facts["phase"])
    if facts.get("source_object_id") is not None:
        _check_attributed_source(context, source_id)
    require(content.encode() in prompt, "rendered prompt omits the decision governance content")
    require(facts.get("context_digest") == domain_digest(CONTEXT_PROTOCOL, _canonical_bytes(context)),
            "decision governance context digest mismatch")
    require(facts.get("model_request_digest") == domain_digest("tn.llama.model-request.v1", body),
            "model request digest mismatch")
    require(facts.get("rendered_prompt_digest") == domain_digest("tn.llama.rendered-prompt.v1", prompt),
            "rendered prompt digest mismatch")
    _check_token_manifest(facts, manifest)
    # Source attribution and semantic verification are recorded by the native admission event.
    check_source(facts, source_id)


def _check_attributed_source(context, source_id):
    require(context.get("schema") == "tn.llama.decision-context.v1",
            "native object context has an unrecognized semantic schema")
    sources = context.get("sources")
    require(isinstance(sources, list) and all(isinstance(item, dict) for item in sources),
            "native context lacks attributed sources")
    matching = [item for item in sources if item.get("object_id") == source_id]
    require(len(matching) == 1 and isinstance(matching[0].get("governance"), dict)
            and bool(matching[0]["governance"]),
            "native context semantics do not belong to the admitted source")


def _check_token_manifest(facts, manifest):
    """The manifest of the actual prompt tokens belongs to this execution and matches its digest."""
    identity = facts.get("execution_identity")
    if isinstance(identity, dict) and identity.get("backend") == "vllm":
        domain, tokens = "tn.vllm.execution.v1", manifest.get("prompt_token_ids")
        require(all(manifest.get(key) == identity[key]
                    for key in ("engine_instance", "request_id", "external_request_id")),
                "vLLM token manifest belongs to another execution")
    else:
        domain, tokens = "tn.llama.runnable-task.v1", manifest.get("task", {}).get("tokens")
    require(manifest.get("schema") == domain and isinstance(tokens, list) and bool(tokens)
            and all(type(token) is int for token in tokens), "missing actual prompt token manifest")
    require(facts.get("runnable_task_digest") == domain_digest(domain, _canonical_bytes(manifest)),
            "runnable token manifest digest mismatch")


def _generated_call(raw):
    """The one tool call the model generated; any other generated content is refused."""
    match = _TOOL_CALL.fullmatch(raw)
    require(match is not None and "<tool_call>" not in match[1], "the model's output is not exactly one tool call")
    call = parse_json(match[1])
    require(isinstance(call, dict) and set(call) == {"name", "arguments"}, "the model's tool call is malformed")
    return call


def _decrypt_call(request):
    """Return the model's retained decrypt call and the runtime's answer to it."""
    messages = request.get("messages", [])
    calls = [
        index for index, message in enumerate(messages)
        if message.get("role") == "assistant"
        and [call.get("function", {}).get("name") for call in message.get("tool_calls", [])] == [_DECRYPT_TOOL]
    ]
    require(len(calls) == 1 and calls[0] + 1 < len(messages), "governed action lacks exactly one decrypt call")
    call, answer = messages[calls[0]]["tool_calls"][0], messages[calls[0] + 1]
    require(answer.get("role") == "tool" and answer.get("tool_call_id") == call.get("id"),
            "decrypted values are not the answer to the model's call")
    return parse_json(call["function"]["arguments"]), parse_json(answer["content"])


def _decrypt_control(request, phase):
    """Return the decrypt turn's control fields, which carry no business value."""
    _, control = _control_message(request, phase)
    entries = control.get("encrypted_data")
    require(set(control) == _DECRYPT_CONTROL and isinstance(entries, list) and bool(entries)
            and all(set(item) == _ENCRYPTED_FIELD for item in entries),
            "decrypt turn lacks the hash keys or holds other data")
    return control


def _check_signed_hash_keys(control, envelope, governance_hash_key=None):
    """The hash keys shown to the model are the signed object's own."""
    require(envelope is not None, "native evidence needs the signed source object")
    require(_governance_key_matches(control, envelope, governance_hash_key)
            and all(item["data_hash"] == envelope[item["group"]]["field_hashes"][item["field"]]
                    for item in control["encrypted_data"]),
            "decrypt turn hash keys differ from the signed source object")


def _governance_key_matches(control, envelope, expected):
    """A bound object's key names its exact governance, so only its reader can supply it."""
    labels = parse_json(envelope["tn_aad"].encode()) if "tn_aad" in envelope else {}
    if "binding" in labels.get("tn.agents", {}):
        return expected is not None and control["governance_hash"] == expected
    return control["governance_hash"] == envelope["tn.agents"]["field_hashes"]["policy"]


def _text_values(value):
    if isinstance(value, dict):
        value = list(value.values())
    if isinstance(value, list):
        return [text for item in value for text in _text_values(item)]
    return [value] if isinstance(value, str) and len(value) >= 8 else []


def check_decrypt_turn(turns, source_envelope, governance_hash_key=None):
    """The model was shown the governance, then generated the call that presents its hash keys."""
    (phase, start, result, _), *actions = turns
    require(phase == 3 and bool(actions), "values opened without the model's decrypt call")
    request = parse_json(retained_bytes(start, "request_json_b64"))
    tools = [tool.get("function", {}).get("name") for tool in request.get("tools", [])]
    require(tools == [_DECRYPT_TOOL]
            and all(item.get("role") in {"system", "user"} for item in request.get("messages", [])),
            "decrypt turn offers another tool or already holds a tool result")
    control = _decrypt_control(request, phase)
    _check_signed_hash_keys(control, source_envelope, governance_hash_key)
    governance_hash = control["governance_hash"]
    offered = {(item["group"], item["field"]): item["data_hash"] for item in control["encrypted_data"]}
    generated = _generated_call(retained_bytes(result, "raw_model_output_b64").decode())
    require(generated["name"] == _DECRYPT_TOOL, "the model's output holds no decrypt call")
    prompt = retained_bytes(start, "rendered_prompt_b64").decode()
    for _, action, _, _ in actions:
        presented, answer = _decrypt_call(parse_json(retained_bytes(action, "request_json_b64")))
        require(presented == generated["arguments"], "generated decrypt call differs from the retained assistant call")
        hashes = presented.get("data_hashes")
        require(presented.get("governance_hash") == governance_hash and answer.get("governance_hash") == governance_hash,
                "decrypt call does not present the governance hash key shown to the model")
        require(isinstance(hashes, list) and bool(hashes) and set(hashes) <= set(offered.values()),
                "decrypt call does not present the data hash keys the model generated")
        returned = {offered.get((group, field)) for group, fields in answer.get("data", {}).items()
                    for field in fields}
        require(returned == set(hashes), "decrypt result differs from the fields the model presented")
        require(not any(text in prompt for text in _text_values(answer.get("data"))),
                "a decrypted value appears before the model's decrypt call")
