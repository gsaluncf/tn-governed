"""Measure dependent tools after a retained SQL/Polars/scalar/model workload."""

from __future__ import annotations

import hashlib
import json
import time
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path

from tn_governed.endpoints import Endpoint
from tn_governed.publications import write_once
from tn_governed.tool_runtime import Call, ToolRegistry, ToolSpec, ToolWorkflow
from tn_governed.values.evidence import verify_tape
from tn_governed.values.runtime import Assessment, ObligationResult

from .report_acceptance import accepted_report_evidence

TOOL_OPERATION = "tool.register_review"
DESTINATION = "benchmark-review"
LEDGER_ACTION = "performance.release_ledger"
REGISTER_SCHEMA = {
    "type": "object",
    "properties": {"sequence": {"type": "integer", "minimum": 1}},
    "required": ["sequence"],
    "additionalProperties": False,
}
RECEIPT_SCHEMA = {
    "type": "object",
    "properties": {
        "sequence": {"type": "integer", "minimum": 1},
        "input_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "receipt": {"type": "string", "minLength": 1},
        "status": {"const": "queued"},
    },
    "required": ["sequence", "input_sha256", "receipt", "status"],
    "additionalProperties": False,
}
def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _save(path, value):
    write_once(path, json.dumps(value, indent=2, allow_nan=False).encode())


def _policies(endpoint, artifact):
    publication = endpoint.store.read(artifact.reference.object_id)
    return tuple(endpoint.session.governance(publication).governance.policies)


def _policy_ids(policies):
    return sorted(
        (policy.governed_by, policy.policy_ref, policy.revision_id) for policy in policies
    )


def _admit_scalar(context, source):
    """Apply an explicit local grant for internal review operations.

    The grant retains admitted source contracts and claim attribution. It covers
    the named tool workload rather than interpreting prose or reusing SQL grants.
    """
    data, _, claims = context._metadata(source)
    policies = tuple(data.policies)
    writers = frozenset(context.evaluator.writers) | {context.session.did}

    def accepts(presented):
        return bool(presented) and all(
            any(policy.matches_contract(expected) for expected in policies) for policy in presented
        )

    def evaluate(request):
        permit = (
            request.operation
            in {"import", "model.accept_report", TOOL_OPERATION, "workflow.release", "reveal"}
            and all(writer in writers for writer in request.writers)
            and accepts(request.policies)
            and request.application == "tool-performance"
            and request.purpose == "internal-review"
            and request.destination
            in {
                "governed-runtime",
                "governed-tool-runtime",
                "tool:register_review",
                DESTINATION,
            }
        )
        return Assessment(permit, "configured internal tool workload")

    endpoint = Endpoint(
        session=context.session,
        store=context.recorder.store,
        evidence_policy=context.recorder.policy,
        evidence_policies=(context.recorder.policy,),
        evaluator=evaluate,
        application="tool-performance",
        purpose="internal-review",
        accept_metadata=lambda request: request.writer in writers and accepts(request.policies),
    )
    artifact = endpoint.import_publication(
        context.store_object(source.reference.object_id),
        group=source.reference.group,
        field=source.reference.field,
        claims=tuple(claim.id for claim in claims),
    )
    return endpoint, artifact, claims


def integrate_chain(context, report, source, depth, directory):
    """Admit the completed application result and execute a dependent tool chain.

    NativeModelEndpoint has already admitted the model report and registered its
    required review. This trusted adapter binds its accepted plaintext to that
    signed evidence. Exact native report, tool and acceptance records travel in
    the bridge parameters; source policies and claims travel through its input.
    """
    if type(depth) is not int or depth < 1:
        raise ValueError("tool depth must be a positive integer")
    wall_started = time.perf_counter()
    initial_sizes = context.recorder.store.publication_sizes()
    bridge_started = time.perf_counter()
    endpoint, admitted, claims = _admit_scalar(context, source)
    if report is not None:
        evidence = accepted_report_evidence(
            context, report, source, claims, Path(directory).parent,
        )
        admitted = endpoint.execute(
            "model.accept_report",
            (admitted,),
            lambda _: report.report_html,
            parameters={"accepted_native_report": evidence},
            destination="governed-tool-runtime",
        )
    bridge_seconds = time.perf_counter() - bridge_started
    bridge_records = len(endpoint.store.record_ids(endpoint.recorder.context_id))
    bridge_sizes = endpoint.store.publication_sizes()
    bridge_bytes = sum(
        size for identity, size in bridge_sizes.items() if identity not in initial_sizes
    )
    result = measure_chain(endpoint, admitted, depth, directory)
    result.update(
        bridge_seconds=bridge_seconds,
        processing_seconds=bridge_seconds + result["tool_seconds"],
        integration_wall_seconds=time.perf_counter() - wall_started,
        integrated_signed_records=bridge_records + result.get("signed_records", 0),
        integrated_added_native_bytes=bridge_bytes + result.get("added_native_bytes", 0),
        native_report_id=report.object.id if report is not None else None,
        bridge_artifact=admitted.to_dict(),
    )
    _save(Path(directory) / "integration.json", result)
    return result


@dataclass(frozen=True)
class _Before:
    """The endpoint's retained objects and the source's attribution before the chain runs."""

    sizes: dict
    record_ids: frozenset
    policies: tuple
    claims: object

    @classmethod
    def of(cls, endpoint, source):
        return cls(endpoint.store.publication_sizes(),
                   frozenset(endpoint.store.record_ids(endpoint.recorder.context_id)),
                   _policies(endpoint, source), endpoint.claims(source))


class _ReceiptChain:
    """Dependent review registrations; each call consumes its predecessor's durable receipt."""

    def __init__(self, endpoint, directory):
        if LEDGER_ACTION in endpoint.obligations:
            raise ValueError("measurement ledger action is already registered")
        self.endpoint, self.directory, self.receipts = endpoint, directory, []
        self.previous_evaluator = endpoint.evaluator

    @contextmanager
    def installed(self):
        """Require the ledger action on release while the chain runs."""
        self.endpoint.evaluator = self._evaluate
        self.endpoint.obligations[LEDGER_ACTION] = self._ledger
        try:
            yield
        finally:
            self.endpoint.evaluator = self.previous_evaluator
            del self.endpoint.obligations[LEDGER_ACTION]

    def run(self, source, depth):
        """Execute `depth` dependent registrations and release the last receipt."""
        tools = ToolRegistry((ToolSpec("register_review", REGISTER_SCHEMA, RECEIPT_SCHEMA,
                                       self._register, operation=TOOL_OPERATION),))
        workflow = ToolWorkflow(self.endpoint, tools, {"source": source},
                                required_tools=("register_review",), max_calls=depth)
        completions = []
        for sequence in range(1, depth + 1):
            predecessor = completions[-1] if completions else None
            completions.append(workflow.execute(Call(
                "review-" + str(sequence),
                "register_review",
                {"sequence": sequence},
                (predecessor.handle if predecessor else "source",),
                (predecessor.call_id,) if predecessor else (),
            )))
        output = workflow.finish(self.receipts[-1], schema=RECEIPT_SCHEMA, destination=DESTINATION)
        return workflow, completions, output

    def _register(self, invocation):
        value = invocation.values[0]
        sequence = invocation.arguments["sequence"]
        if sequence > 1 and (not isinstance(value, dict) or value.get("sequence") != sequence - 1):
            raise ValueError("review registration does not follow its predecessor receipt")
        filename = hashlib.sha256(invocation.idempotency_key.encode()).hexdigest() + ".json"
        receipt = {
            "sequence": sequence,
            "input_sha256": hashlib.sha256(_wire(value)).hexdigest(),
            "receipt": "receipts/" + filename,
            "status": "queued",
        }
        _save(self.directory / receipt["receipt"], {
            "receipt": receipt,
            "binding": invocation.binding,
            "idempotency_key": invocation.idempotency_key,
        })
        self.receipts.append(receipt)
        return receipt

    def _ledger(self, request):
        content = _wire({
            "application": request.application,
            "purpose": request.purpose,
            "operation": request.operation,
            "inputs": [item.to_dict() for item in request.inputs],
            "parameters": request.parameters,
        })
        digest = hashlib.sha256(content).hexdigest()
        write_once(self.directory / "ledger" / (digest + ".json"), content)
        return ObligationResult(True, "sha256:" + digest)

    def _evaluate(self, request):
        assessment = self.previous_evaluator(request)
        if assessment.permit and request.operation == "workflow.release":
            return replace(assessment, obligations=assessment.obligations + (LEDGER_ACTION,))
        return assessment


def measure_chain(endpoint, source, depth, directory):
    """Time registration calls, their checks, required ledger action, and governed release.

    Source admission, endpoint enrollment, final verification, ordinary disclosure,
    and measurement export are outside the timed interval. Each registration writes
    a durable receipt for its exact opened input; the next call consumes that receipt.
    """
    if type(depth) is not int or depth < 1:
        raise ValueError("tool depth must be a positive integer")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    before = _Before.of(endpoint, source)
    chain = _ReceiptChain(endpoint, directory)
    result = {"depth": depth, "completed": False, "verified": False}
    started = time.perf_counter()
    try:
        with chain.installed():
            workflow, completions, output = chain.run(source, depth)
            result["tool_seconds"] = time.perf_counter() - started
            result["completed"] = True
            added_ids, footprint = _footprint(endpoint, before, output, chain.receipts)
            result.update(footprint)
            verification_started = time.perf_counter()
            facts = _verify_chain(endpoint, before, (workflow, completions, output),
                                  chain.receipts[-1], depth, added_ids)
            result.update(verified=True, verification_seconds=time.perf_counter() - verification_started,
                          **facts)
            endpoint.recorder.export(directory / "tape")
    except Exception as exc:
        result["completed"] = result["verified"] = False
        result.setdefault("tool_seconds", time.perf_counter() - started)
        result["error_type"] = type(exc).__name__
    _save(directory / "measurement.json", result)
    return result


def _footprint(endpoint, before, output, receipts):
    """The signed records and native bytes the chain added, and its released output."""
    sizes = endpoint.store.publication_sizes()
    added_ids = set(endpoint.store.record_ids(endpoint.recorder.context_id)) - before.record_ids
    return added_ids, {
        "signed_records": len(added_ids),
        "added_native_bytes": sum(
            size for identity, size in sizes.items() if identity not in before.sizes
        ),
        "retained_native_bytes": sum(sizes.values()),
        "output_publication_bytes": sizes[output.reference.object_id],
        "output": output.to_dict(),
        "receipt_count": len(receipts),
    }


def _verify_chain(endpoint, before, run, final_receipt, depth, added_ids):
    """The release keeps the source's claims and policies, the requested depth, and its ledger action."""
    workflow, completions, output = run
    records = verify_tape(
        endpoint.recorder.records(),
        session=endpoint.session,
        policy=endpoint.recorder.policy,
        expected_writer=endpoint.session.did,
        expected_context=endpoint.recorder.context_id,
        expected_head=endpoint.recorder.head,
    )
    manifest = endpoint.metadata(output)
    if endpoint.claims(output) != before.claims:
        raise AssertionError("released tool chain lost source claim attribution")
    if _policy_ids(_policies(endpoint, output)) != _policy_ids(before.policies):
        raise AssertionError("released tool chain changed its source policy union")
    observed_depth, calls = _call_graph(endpoint, completions)
    completed_events = [event for event in workflow.events if event["kind"] == "tool_completed"]
    if observed_depth != depth or len(completed_events) != depth:
        raise AssertionError("signed completed graph differs from requested tool depth")
    actions = _ledger_actions(endpoint, output, manifest)
    if endpoint.reveal(output, destination=DESTINATION) != final_receipt:
        raise AssertionError("released receipt differs from the completed tool result")
    return {
        "observed_depth": observed_depth,
        "calls": calls,
        "claims": [claim.id for claim in before.claims],
        "policy_count": len(before.policies),
        "required_action_count": len(actions),
        "required_action_record_id": output.decision_id,
        "action_records": manifest["action_records"],
        "record_kinds": dict(
            Counter(record.body["kind"] for record in records if record.id in added_ids)
        ),
        "events": list(workflow.events),
    }


def _call_graph(endpoint, completions):
    """The longest signed dependency chain, and each call's signed decision and result."""
    observed, calls = {}, []
    for completion in completions:
        binding = endpoint.metadata(completion.artifact)["parameters"]["tool_call"]
        dependencies = binding["dependencies"]
        observed[completion.call_id] = 1 + max(
            (observed[item] for item in dependencies), default=0
        )
        calls.append({
            "id": completion.call_id,
            "dependencies": dependencies,
            "decision_id": completion.artifact.decision_id,
            "result_id": completion.artifact.result_id,
        })
    return max(observed.values()), calls


def _ledger_actions(endpoint, output, manifest):
    decision = endpoint.read_record(output.decision_id)
    actions = [
        item
        for item in decision.body["details"]["discharged"]
        if item["obligation"] == LEDGER_ACTION and item["satisfied"] is True
    ]
    if len(actions) != 1 or output.decision_id not in manifest["action_records"]:
        raise AssertionError("workflow release lacks its required ledger completion")
    return actions
