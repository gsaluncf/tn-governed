"""Correlate a run's runtime actions and terminal release with its authorized model turns."""

from __future__ import annotations

from tn.canonical import _canonical_bytes

from .context_artifacts import (
    audit_facts,
    check_identity,
    check_ordered,
    execution_key,
    parse_json,
    require,
    retained_bytes,
)

# The runtime executes protected tools itself; only the model's decrypt call selects sections.
_RUNTIME_ACTION_EVENTS = {"governed_tool_executed_runtime", "tool_result_accepted_runtime"}
_RELEASED_ACTIONS = {
    "sections_selected": "sections_selected",
    "tool_executed": "governed_tool_executed",
    "tool_executed_runtime": "governed_tool_executed_runtime",
}
_RECEIPT_FIELDS = ("task_id", "slot_id", "tool_name", "event_id", "row_hash", "selected_sections")
_MODEL_FACTS = ("phase", "turn_ordinal", "execution_identity", "model_request_digest",
                "rendered_prompt_digest", "runnable_task_digest", "context_digest")


def check_runtime_actions(audit, admission, *, run_id, request_digest, source_id):
    """Runtime tool actions run inside the admitted computation, outside every model turn."""
    require(not any(row.get("kind") == "sections_selected_runtime" for row in audit),
            "native evidence opens values only through the model's decrypt call")
    runtime = [row for row in audit if row.get("kind") in _RUNTIME_ACTION_EVENTS]
    emitted = [row for row in audit if row.get("kind") == "output_emitted_and_read_back"]
    for row in runtime:
        check_identity(row, run_id, request_digest, source_id)
        facts = audit_facts(row)
        require(row.get("llama_task_id") is None and row.get("llama_slot_id") is None
                and all(facts.get(key) is None for key in _MODEL_FACTS),
                "runtime action is incorrectly assigned to model inference")
        require(admission["sequence"] < row["sequence"] and all(row["sequence"] < item["sequence"] for item in emitted),
                "runtime action is outside the admitted computation")
    require(len(runtime) % 2 == 0, "runtime tool execution lacks its accepted result")
    for executed, accepted in zip(runtime[::2], runtime[1::2], strict=True):
        digest = audit_facts(executed).get("content_digest")
        require(executed["kind"] == "governed_tool_executed_runtime"
                and accepted["kind"] == "tool_result_accepted_runtime"
                and isinstance(digest, str) and bool(digest)
                and audit_facts(accepted).get("content_digest") == digest,
                "runtime tool result is not bound to its execution")


def check_completion(audit, trace, binding, *, run_id, source_id, expected_release):
    """The last governed decision emitted the report, completed, and is the retained release."""
    emitted = [row for row in audit if row.get("kind") == "output_emitted_and_read_back"]
    completed = [row for row in audit if row.get("kind") == "standalone_use_completed"]
    require(len(emitted) == len(completed) == 1,
            "report completion requires one emission and one terminal audit event")
    facts = audit_facts(binding)
    identity = execution_key(binding, facts)
    require(facts.get("phase") == 4
            and all(execution_key(row, audit_facts(row)) == identity for row in (*emitted, *completed))
            and binding["sequence"] < emitted[0]["sequence"] < completed[0]["sequence"],
            "report completion is not bound to the last governed decision")
    require(not any(row.get("kind") == "terminal_error" and row.get("request_digest") == binding.get("request_digest")
                    for row in audit), "completed report evidence contains a terminal error")
    payload, client_trace = _terminal_release(trace, binding, run_id=run_id, source_id=source_id)
    _check_released_actions(audit, client_trace, source_id=source_id)
    _check_output_delivery(client_trace, binding, payload["output_object_id"])
    if expected_release is not None:
        require(isinstance(expected_release, dict) and _canonical_bytes(payload) == _canonical_bytes(expected_release),
                "retained release differs from the received report publication")


def _terminal_release(trace, binding, *, run_id, source_id):
    """The one retained release, last in the trace, naming the admitted source and its output."""
    releases = [row for row in trace if row.get("kind") == "release"]
    require(len(releases) == 1, "report completion lacks one retained release")
    release = releases[0]
    require(release is trace[-1] and release.get("run_id") == run_id and release.get("phase") == 4
            and release.get("task_id") == binding.get("llama_task_id")
            and release.get("slot_id") == binding.get("llama_slot_id"),
            "retained release is not the terminal result of the report inference")
    payload = parse_json(retained_bytes(release, "parsed_content_b64"))
    require(isinstance(payload, dict) and payload.get("protocol") == "tn.llama.release.v2"
            and payload.get("run_id") == run_id and payload.get("source_object_id") == source_id
            and isinstance(payload.get("output_object_id"), str) and bool(payload["output_object_id"]),
            "retained release does not identify the admitted source and output")
    client_trace = payload.get("trace")
    require(isinstance(client_trace, list) and all(isinstance(item, dict) for item in client_trace),
            "retained release lacks its execution trace")
    return payload, client_trace


def _check_output_delivery(client_trace, binding, output_id):
    readbacks = [item for item in client_trace if item.get("event") == "output_readback"]
    deliveries = [item for item in client_trace if item.get("event") == "release"]
    require(
        len(readbacks) == len(deliveries) == 1
        and client_trace.index(readbacks[0]) < client_trace.index(deliveries[0])
        and deliveries[0] is client_trace[-1]
        and deliveries[0].get("state") == "complete"
        and all(item.get("task_id") == binding.get("llama_task_id")
                and item.get("slot_id") == binding.get("llama_slot_id")
                and item.get("row_hash") == output_id and item.get("event_id") == output_id
                for item in (*readbacks, *deliveries)),
        "release trace does not bind the output publication to the report inference",
    )


def _check_released_actions(audit, client_trace, *, source_id):
    """The release's action history is the audit's, and each tool has its inserted receipt."""
    check_ordered([{"sequence": item.get("ordinal")} for item in client_trace], "release trace")
    actions = [item for item in client_trace if item.get("event") in _RELEASED_ACTIONS]
    recorded = [row for row in audit if row.get("kind") in _RELEASED_ACTIONS.values()]
    require(len(actions) == len(recorded), "release action history differs from the retained audit history")
    for item, row in zip(actions, recorded, strict=True):
        require(_RELEASED_ACTIONS[item["event"]] == row["kind"]
                and item.get("task_id") == row.get("llama_task_id")
                and item.get("slot_id") == row.get("llama_slot_id")
                and item.get("state") == "governed_action",
                "release action differs from its authorized audit execution")
        if item["event"] == "sections_selected":
            require(item.get("row_hash") == source_id, "release selection belongs to another admitted source")
    _check_tool_receipts(actions, client_trace)
    _check_native_acceptance(audit)


def _check_tool_receipts(actions, client_trace):
    tools = [item for item in actions if item["event"].startswith("tool_executed")]
    receipts = [item for item in client_trace if item.get("event") == "receipt_inserted"]
    require(len(tools) == len(receipts), "release tool history lacks exact inserted receipts")
    for index, (tool, receipt) in enumerate(zip(tools, receipts, strict=True)):
        next_tool = tools[index + 1]["ordinal"] if index + 1 < len(tools) else float("inf")
        require(tool["ordinal"] < receipt["ordinal"] < next_tool
                and all(isinstance(tool.get(key), str) and tool[key] for key in ("tool_name", "event_id", "row_hash"))
                and all(receipt.get(key) == tool.get(key) for key in _RECEIPT_FIELDS),
                "release receipt is not bound to its tool execution")


def _check_native_acceptance(audit):
    executed = [row for row in audit if row.get("kind") == "governed_tool_executed"]
    accepted = [row for row in audit if row.get("kind") == "tool_result_accepted"]
    require(len(executed) == len(accepted), "native tool history lacks accepted results")
    for execution, acceptance in zip(executed, accepted, strict=True):
        facts, accepted_facts = audit_facts(execution), audit_facts(acceptance)
        require(execution["sequence"] < acceptance["sequence"]
                and execution_key(execution, facts) == execution_key(acceptance, accepted_facts)
                and facts.get("content_digest") == accepted_facts.get("content_digest"),
                "native tool result differs from its executed action")
