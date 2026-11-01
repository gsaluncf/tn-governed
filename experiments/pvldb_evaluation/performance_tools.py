"""Measure dependent tools after a retained SQL/Polars/scalar/model workload."""

from __future__ import annotations

import hashlib
import json
import statistics
import time
from collections import Counter
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from tn_governed.endpoints import Endpoint
from tn_governed.publications import write_once
from tn_governed.tool_runtime import Call, ToolRegistry, ToolSpec, ToolWorkflow
from tn_governed.values.evidence import EvidenceError, verify_tape
from tn_governed.values.runtime import Assessment, ObligationResult

TOOL_OPERATION = "tool.register_review"
DESTINATION = "benchmark-review"
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


def _accepted_report_evidence(context, report, source, claims):
    """Bind a trusted recipient's accepted HTML to carried signed native evidence."""
    store = context.recorder.store
    result = context.recorder.read(report.result_record_id)
    handoff = context.recorder.read(report.handoff_record_id)
    decision = context.recorder.read(report.decision_id)
    records = (decision, handoff, result)
    if any(record.writer != context.session.did for record in records):
        raise EvidenceError("model acceptance record has an unexpected writer")
    if [record.body["kind"] for record in records] != ["Decision", "ModelHandoff", "ModelResult"]:
        raise EvidenceError("model acceptance record kinds are inconsistent")
    if (
        len({record.body["call_id"] for record in records}) != 1
        or len({record.body["context_id"] for record in records}) != 1
        or not decision.body["sequence"] < handoff.body["sequence"] < result.body["sequence"]
    ):
        raise EvidenceError("model acceptance records do not identify one ordered invocation")
    digest = hashlib.sha256(report.report_html.encode()).hexdigest()
    rd, hd = result.body["details"], handoff.body["details"]
    expected_tools = [item.id for item in report.release.tool_objects]
    if (
        decision.body["details"].get("permitted") is not True
        or hd.get("subject") != source.reference.to_dict()
        or hd.get("decision_id") != decision.id
        or hd.get("delivery") != "prepared-for-submit"
        or hd.get("input_wire_sha256")
        != hashlib.sha256(store.get(source.reference.object_id)).hexdigest()
        or rd.get("input_object_id") != source.reference.object_id
        or rd.get("output_object_id") != report.object.id
        or rd.get("report_html_sha256") != digest
        or rd.get("decision_id") != decision.id
        or rd.get("handoff_record_id") != handoff.id
        or set(rd.get("claims", ())) != {claim.id for claim in claims}
        or rd.get("tool_object_ids") != expected_tools
        or report.release.output_object.id != report.object.id
    ):
        raise EvidenceError("accepted model report differs from its signed invocation")
    for publication in (report.object, *report.release.tool_objects):
        if store.get(publication.id) != publication.forward():
            raise EvidenceError("accepted model publication differs from retained native bytes")
    if report.review is None:
        raise EvidenceError("market report requires a completed review registration")
    review = context.recorder.read(report.review.record_id)
    vd, vb = review.body["details"], review.body
    if (
        review.writer != result.writer
        or vb["kind"] != "ReviewRequested"
        or vb["call_id"] != result.body["call_id"]
        or vb["context_id"] != result.body["context_id"]
        or not handoff.body["sequence"] < vb["sequence"] < result.body["sequence"]
        or rd.get("review_request_id") != review.id
        or vd.get("decision_id") != decision.id
        or vd.get("handoff_record_id") != handoff.id
        or vd.get("input_object_id") != source.reference.object_id
        or vd.get("report_object_id") != report.object.id
        or vd.get("report_html_sha256") != digest
        or vd.get("status") != "pending"
        or report.review.status != "pending"
        or report.review.report_object_id != report.object.id
        or vd.get("review_action", {}).get("assignee") != report.review.assignee
        or vd.get("review_action", {}).get("reason") != report.review.reason
    ):
        raise EvidenceError("review registration differs from its accepted report")
    queue_root = store.root.parent.resolve()
    queue_path = (queue_root / report.review.queue_entry).resolve()
    if not queue_path.is_relative_to(queue_root) or queue_path.read_bytes() != store.get(review.id):
        raise EvidenceError("review queue does not retain its exact signed registration")
    return {
        "report_object_id": report.object.id,
        "report_html_sha256": digest,
        "source": source.reference.to_dict(),
        "recipient_acceptance_record_id": result.id,
        "review_registration_record_id": review.id,
        "native_publications": [
            item.forward().decode("utf-8") for item in (report.object, *report.release.tool_objects)
        ],
        "acceptance_records": [
            store.get(record.id).decode("utf-8") for record in (*records, review)
        ],
    }


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
        evidence = _accepted_report_evidence(context, report, source, claims)
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
    prior_sizes = endpoint.store.publication_sizes()
    prior_ids = set(endpoint.store.record_ids(endpoint.recorder.context_id))
    source_policies = _policies(endpoint, source)
    source_claims = endpoint.claims(source)
    previous_evaluator = endpoint.evaluator
    action_name = "performance.release_ledger"
    if action_name in endpoint.obligations:
        raise ValueError("measurement ledger action is already registered")
    receipts = []

    def register(invocation):
        value = invocation.values[0]
        sequence = invocation.arguments["sequence"]
        if sequence > 1 and (not isinstance(value, dict) or value.get("sequence") != sequence - 1):
            raise ValueError("review registration does not follow its predecessor receipt")
        digest = hashlib.sha256(_wire(value)).hexdigest()
        filename = hashlib.sha256(invocation.idempotency_key.encode()).hexdigest() + ".json"
        receipt = {
            "sequence": sequence,
            "input_sha256": digest,
            "receipt": "receipts/" + filename,
            "status": "queued",
        }
        _save(
            directory / receipt["receipt"],
            {
                "receipt": receipt,
                "binding": invocation.binding,
                "idempotency_key": invocation.idempotency_key,
            },
        )
        receipts.append(receipt)
        return receipt

    def ledger(request):
        content = _wire(
            {
                "application": request.application,
                "purpose": request.purpose,
                "operation": request.operation,
                "inputs": [item.to_dict() for item in request.inputs],
                "parameters": request.parameters,
            }
        )
        digest = hashlib.sha256(content).hexdigest()
        write_once(directory / "ledger" / (digest + ".json"), content)
        return ObligationResult(True, "sha256:" + digest)

    def evaluate(request):
        assessment = previous_evaluator(request)
        if assessment.permit and request.operation == "workflow.release":
            return replace(assessment, obligations=assessment.obligations + (action_name,))
        return assessment

    tools = ToolRegistry(
        (
            ToolSpec(
                "register_review",
                {
                    "type": "object",
                    "properties": {"sequence": {"type": "integer", "minimum": 1}},
                    "required": ["sequence"],
                    "additionalProperties": False,
                },
                RECEIPT_SCHEMA,
                register,
                operation=TOOL_OPERATION,
            ),
        )
    )
    endpoint.evaluator = evaluate
    endpoint.obligations[action_name] = ledger
    result = {"depth": depth, "completed": False, "verified": False}
    started = time.perf_counter()
    try:
        workflow = ToolWorkflow(
            endpoint,
            tools,
            {"source": source},
            required_tools=("register_review",),
            max_calls=depth,
        )
        completions = []
        for sequence in range(1, depth + 1):
            predecessor = completions[-1] if completions else None
            call = Call(
                "review-" + str(sequence),
                "register_review",
                {"sequence": sequence},
                (predecessor.handle if predecessor else "source",),
                (predecessor.call_id,) if predecessor else (),
            )
            completions.append(workflow.execute(call))
        output = workflow.finish(receipts[-1], schema=RECEIPT_SCHEMA, destination=DESTINATION)
        result["tool_seconds"] = time.perf_counter() - started
        result["completed"] = True
        sizes = endpoint.store.publication_sizes()
        record_ids = endpoint.store.record_ids(endpoint.recorder.context_id)
        added_ids = set(record_ids) - prior_ids
        result.update(
            signed_records=len(added_ids),
            added_native_bytes=sum(
                size for identity, size in sizes.items() if identity not in prior_sizes
            ),
            retained_native_bytes=sum(sizes.values()),
            output_publication_bytes=sizes[output.reference.object_id],
            output=output.to_dict(),
            receipt_count=len(receipts),
        )
        verification_started = time.perf_counter()
        records = verify_tape(
            endpoint.recorder.records(),
            session=endpoint.session,
            policy=endpoint.recorder.policy,
            expected_writer=endpoint.session.did,
            expected_context=endpoint.recorder.context_id,
            expected_head=endpoint.recorder.head,
        )
        manifest = endpoint.metadata(output)
        if endpoint.claims(output) != source_claims:
            raise AssertionError("released tool chain lost source claim attribution")
        if _policy_ids(_policies(endpoint, output)) != _policy_ids(source_policies):
            raise AssertionError("released tool chain changed its source policy union")
        observed, calls = {}, []
        for completion in completions:
            binding = endpoint.metadata(completion.artifact)["parameters"]["tool_call"]
            dependencies = binding["dependencies"]
            observed[completion.call_id] = 1 + max(
                (observed[item] for item in dependencies), default=0
            )
            calls.append(
                {
                    "id": completion.call_id,
                    "dependencies": dependencies,
                    "decision_id": completion.artifact.decision_id,
                    "result_id": completion.artifact.result_id,
                }
            )
        observed_depth = max(observed.values())
        completed_events = [event for event in workflow.events if event["kind"] == "tool_completed"]
        if observed_depth != depth or len(completed_events) != depth:
            raise AssertionError("signed completed graph differs from requested tool depth")
        decision = endpoint.read_record(output.decision_id)
        actions = [
            item
            for item in decision.body["details"]["discharged"]
            if item["obligation"] == action_name and item["satisfied"] is True
        ]
        if len(actions) != 1 or output.decision_id not in manifest["action_records"]:
            raise AssertionError("workflow release lacks its required ledger completion")
        if endpoint.reveal(output, destination=DESTINATION) != receipts[-1]:
            raise AssertionError("released receipt differs from the completed tool result")
        result.update(
            verified=True,
            verification_seconds=time.perf_counter() - verification_started,
            observed_depth=observed_depth,
            calls=calls,
            claims=[claim.id for claim in source_claims],
            policy_count=len(source_policies),
            required_action_count=len(actions),
            required_action_record_id=output.decision_id,
            action_records=manifest["action_records"],
            record_kinds=dict(
                Counter(record.body["kind"] for record in records if record.id in added_ids)
            ),
            events=list(workflow.events),
        )
        endpoint.recorder.export(directory / "tape")
    except Exception as exc:
        result["completed"] = result["verified"] = False
        result.setdefault("tool_seconds", time.perf_counter() - started)
        result["error_type"] = type(exc).__name__
    finally:
        endpoint.evaluator = previous_evaluator
        del endpoint.obligations[action_name]
    _save(directory / "measurement.json", result)
    return result


def summarize_tools(cases):
    summaries = []
    for depth in sorted({case["depth"] for case in cases}):
        measured = [case for case in cases if case["depth"] == depth and not case["warmup"]]
        successful = [case for case in measured if case["completed"] and case["verified"]]
        summaries.append(
            {
                "depth": depth,
                "attempts": len(measured),
                "successful": len(successful),
                "failures": len(measured) - len(successful),
                "median_tool_seconds": statistics.median(
                    case["tool_seconds"] for case in successful
                )
                if successful
                else None,
                "median_signed_records": statistics.median(
                    case["signed_records"] for case in successful
                )
                if successful
                else None,
                "median_added_native_bytes": statistics.median(
                    case["added_native_bytes"] for case in successful
                )
                if successful
                else None,
            }
        )
    baseline = next(
        (
            item["median_tool_seconds"]
            for item in summaries
            if item["depth"] == 1 and not item["failures"]
        ),
        None,
    )
    for item in summaries:
        item["tool_overhead_vs_depth_1"] = (
            item["median_tool_seconds"] / baseline
            if baseline and item["median_tool_seconds"] is not None and not item["failures"]
            else None
        )
    return summaries


def run_tools(source_directory, output_directory, depths=(1, 3, 5), repetitions=5, warmups=1):
    """Retain raw tool-chain trials and separate inherited model timings from tool cost."""
    depths = tuple(depths)
    if (
        not depths
        or any(type(depth) is not int or depth < 1 for depth in depths)
        or len(set(depths)) != len(depths)
        or type(repetitions) is not int
        or repetitions < 1
        or type(warmups) is not int
        or warmups < 0
    ):
        raise ValueError("depths must be unique positive integers with valid repetition counts")
    from .performance_source import open_recipient, prepare_recipient

    source_directory, root = Path(source_directory).resolve(), Path(output_directory).resolve()
    base = json.loads((source_directory / "case-summary.json").read_bytes())
    if not base.get("completed") or not base.get("verified"):
        raise ValueError("tool measurements require a completed verified source workload")
    root.mkdir(parents=True, exist_ok=False)
    result = {
        "schema": "tn.performance-tools.v1",
        "created_utc": datetime.now(UTC).isoformat(),
        "source_directory": str(source_directory),
        "source_rows": base["rows"],
        "source_with_model": base["with_model"],
        "source_timings_seconds": base["timings_seconds"],
        "source_summary_sha256": hashlib.sha256(
            (source_directory / "case-summary.json").read_bytes()
        ).hexdigest(),
        "measurement_contract": {
            "workload": (
                "Dependent durable review-registration receipts "
                "over the retained model-input scalar"
            ),
            "depth": "Longest successful explicit tool-call dependency chain",
            "timed": (
                "ToolWorkflow construction, all tool checks and receipts, "
                "required ledger action, governed release"
            ),
            "untimed": (
                "Endpoint enrollment, retained-source import, final verification/disclosure, "
                "measurement export"
            ),
            "model": (
                "No model request in this interval; source model timing is retained separately"
            ),
            "bytes": (
                "Unique canonical native wire bytes; "
                "additions include snapshots and signed evidence"
            ),
            "records": (
                "Signed operation records added during the timed interval, "
                "excluding creation snapshots"
            ),
            "warmup": (
                "Fresh endpoint and store per trial; "
                "warmup trials are retained and excluded from summaries"
            ),
        },
        "depths": list(depths),
        "repetitions": repetitions,
        "warmups": warmups,
        "cases": [],
    }
    _save(root / "experiment.json", {key: value for key, value in result.items() if key != "cases"})
    for trial in range(warmups + repetitions):
        for depth in depths:
            warmup = trial < warmups
            name = f"{'warmup' if warmup else 'measured'}-{trial + 1}-depth-{depth}"
            directory = root / name
            stage = "enrollment"
            try:
                prepare_recipient(source_directory, directory)
                stage = "source_admission"
                with open_recipient(directory) as prepared:
                    endpoint, admitted, _ = _admit_scalar(prepared["context"], prepared["value"])
                    stage = "tool_chain"
                    case = measure_chain(endpoint, admitted, depth, directory / "tool-chain")
            except Exception as exc:
                case = {
                    "depth": depth,
                    "completed": False,
                    "verified": False,
                    "error_type": type(exc).__name__,
                    "error_stage": stage,
                }
                directory.mkdir(parents=True, exist_ok=True)
                _save(directory / "failure.json", case)
            case = {**case, "warmup": warmup, "trial": trial + 1, "directory": name}
            result["cases"].append(case)
            with (root / "observations.jsonl").open("a", encoding="utf-8") as output:
                output.write(json.dumps(case, allow_nan=False) + "\n")
    result["aggregates"] = summarize_tools(result["cases"])
    result["completed"] = all(case["completed"] and case["verified"] for case in result["cases"])
    _save(root / "measurements.json", result)
    return result
