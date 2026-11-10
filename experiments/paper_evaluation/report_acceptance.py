"""Bind a recipient's accepted report to the signed native invocation that produced it."""

from __future__ import annotations

import hashlib
from pathlib import Path

from tn_governed.values.evidence import EvidenceError


def accepted_report_evidence(context, report, source, claims, queue_root):
    """Bind a trusted recipient's accepted HTML to carried signed native evidence."""
    store = context.recorder.store
    records = _invocation_records(context, report)
    digest = hashlib.sha256(report.report_html.encode()).hexdigest()
    _check_acceptance(store, report, source, claims, records, digest)
    review = _check_review(context, report, source, records, digest)
    queue_root = Path(queue_root).resolve()
    queue_path = (queue_root / report.review.queue_entry).resolve()
    if not queue_path.is_relative_to(queue_root) or queue_path.read_bytes() != store.get(review.id):
        raise EvidenceError("review queue does not retain its exact signed registration")
    return {
        "report_object_id": report.object.id,
        "report_html_sha256": digest,
        "source": source.reference.to_dict(),
        "recipient_acceptance_record_id": records[2].id,
        "review_registration_record_id": review.id,
        "native_publications": [
            item.forward().decode("utf-8") for item in (report.object, *report.release.tool_objects)
        ],
        "acceptance_records": [
            store.get(record.id).decode("utf-8") for record in (*records, review)
        ],
    }


def _invocation_records(context, report):
    """The decision, handoff, and result of one ordered model invocation by this context."""
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
    return records


def _check_acceptance(store, report, source, claims, records, digest):
    """The signed result names this source, report, claims, and tools, and the bytes are retained."""
    decision, handoff, result = records
    rd, hd = result.body["details"], handoff.body["details"]
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
        or rd.get("tool_object_ids") != [item.id for item in report.release.tool_objects]
        or report.release.output_object.id != report.object.id
    ):
        raise EvidenceError("accepted model report differs from its signed invocation")
    for publication in (report.object, *report.release.tool_objects):
        if store.get(publication.id) != publication.forward():
            raise EvidenceError("accepted model publication differs from retained native bytes")


def _check_review(context, report, source, records, digest):
    """The pending review registration belongs to this invocation and its accepted report."""
    decision, handoff, result = records
    if report.review is None:
        raise EvidenceError("market report requires a completed review registration")
    review = context.recorder.read(report.review.record_id)
    rd, vd, vb = result.body["details"], review.body["details"], review.body
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
    return review
