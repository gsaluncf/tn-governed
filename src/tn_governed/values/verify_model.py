"""Offline evidence inspection of a real native model handoff, never a model gate."""

import base64
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

import tn
from tn.canonical import _canonical_bytes
from tn_llama_client.clients import NativeOutputReader
from tn_llama_client.protocol import NativeModelRelease

from ..context_evidence import inspect_governance_context
from .evidence import require
from .model import runtime_limits_from_config
from .report_profile import visible_text

_SCOPE = ("Independent native recipient admission and lineage verification; exact transport and signed "
          "evidence bindings; notice found in unstyled HTML. Native process logs are supporting "
          "observations, not signed remote attestation.")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def verified_context_observation(
    audit, trace, *, run_id, request_digest, source_id, expected_release=None, source_envelope=None,
    governance_hash_key=None,
):
    evidence = inspect_governance_context(
        audit, trace, run_id=run_id, request_digest=request_digest, source_id=source_id,
        expected_release=expected_release, source_envelope=source_envelope,
        governance_hash_key=governance_hash_key,
    )
    require(evidence.verified,
            "native governance context evidence failed: " + "; ".join(evidence.errors))
    return evidence.to_dict()


@dataclass(frozen=True)
class Verified:
    """What the primitive verifier established, for the model checks to build on."""

    root: Path
    model: dict
    records: list
    by_id: dict
    rules: dict
    nodes: dict
    bindings: dict
    store: object
    catalog: object
    dag: object
    resolve: object
    hash_key: object


@dataclass(frozen=True)
class Handoff:
    """The one signed model handoff and what its contributing grants require."""

    record: object
    decision: object
    key: tuple
    source: object
    revisions: list
    declarations: list
    notice: str
    review_action: object

    @property
    def notices(self):
        return {m["required_disclosure"] for m in self.declarations}


@dataclass(frozen=True)
class Exchange:
    """The one retained model HTTP exchange and the runtime's local observations of it."""

    request: dict
    response: dict
    request_digest: str
    audit: list
    observations: dict


def verify_model(root, run, records, by_id, rules, nodes, bindings, store, catalog, dag, resolve, hash_key):
    """`resolve` gives an ancestor's governance view; `hash_key` derives a view's governance
    hash key through the observer's own reader, never from the evidence being checked."""
    ctx = Verified(root, run["model"], records, by_id, rules, nodes, bindings, store, catalog, dag,
                   resolve, hash_key)
    handoff = _handoff(ctx)
    limits, section = _runtime_section(ctx, handoff)
    exchange = _exchange(ctx, handoff)
    results = [r for r in records if r.body["kind"] == "ModelResult"]
    if not ctx.model["completed"]:
        return _failed_run(ctx, handoff, exchange, results)
    result = _model_result(ctx, handoff, exchange, results)
    release, trace = _release(ctx, handoff, exchange, result)
    review = _check_review(ctx, handoff, exchange, result, release, trace)
    visible = _open_report(ctx, handoff, result, release, section, limits, exchange.request_digest)
    outcome = {"completed": True, "input_object_id": handoff.source.id,
               "output_object_id": release.output_object.id,
               "tool_object_ids": [o.id for o in release.tool_objects], "required_disclosure": handoff.notice,
               "visible_report_text": visible, "source_policy_revisions": handoff.revisions,
               "source_claim_ids": bindings[handoff.key]["claims"],
               "native_edges": _native_edges(ctx, handoff, release, section),
               "request_digest": exchange.request_digest, "review": review,
               "native_observations": exchange.observations, "scope": _SCOPE}
    (root / "model-lineage.json").write_text(json.dumps(outcome, indent=2), encoding="utf-8")
    return outcome


def _handoff(ctx):
    """The one handoff names its exact primitive and the governance and claims its Decision considered."""
    handoffs = [r for r in ctx.records if r.body["kind"] == "ModelHandoff"]
    require(len(handoffs) == 1, "demonstration must retain one attempted model submission")
    handoff = handoffs[0]
    hb, hd = handoff.body, handoff.body["details"]
    decision = ctx.by_id[hd["decision_id"]]
    subject = hd["subject"]
    key = subject["object_id"], subject["group"], subject["field"]
    require(key in ctx.bindings and hb["inputs"] == [subject] and hd["delivery"] == "prepared-for-submit",
            "handoff does not identify its exact primitive")
    source = ctx.resolve(key[0]).object
    require(source.id == ctx.model["input_object_id"] and sha(source.forward()) == hd["input_wire_sha256"],
            "handoff input differs from the retained wire")
    revisions = ctx.nodes[key]["policy_revisions"]
    dd = decision.body["details"]
    require(set(revisions) == {p["revision"] for p in dd["policies"]}
            and set(ctx.bindings[key]["claims"]) == set(dd["considered_claims"]),
            "model Decision omitted contributing governance or claims")
    declarations = [ctx.rules[r]["model"] for r in revisions]
    notice, review_action = _check_grants(ctx, handoff, declarations)
    return Handoff(handoff, decision, key, source, revisions, declarations, notice, review_action)


def _check_grants(ctx, handoff, declarations):
    """The handoff keeps every grant's review action, disclosure, and use; return the first two."""
    hb, hd = handoff.body, handoff.body["details"]
    review_actions = [m["review"] for m in declarations if m.get("review") is not None]
    require(not review_actions or all(r == review_actions[0] for r in review_actions),
            "incompatible contributing review actions")
    review_action = review_actions[0] if review_actions else None
    require(hd.get("review_action") == review_action, "handoff dropped the required compensatory action")
    notices = {m["required_disclosure"] for m in declarations}
    # Each original requirement must be present; joining does not rewrite it.
    notice = hd["required_disclosure"]
    require(all(n in notice for n in notices) and notice == ctx.model["required_disclosure"],
            "handoff omitted an original disclosure requirement")
    for grant in declarations:
        require(hb["destination"] in grant["destinations"] and grant["use"] == hd["native_use"] == ctx.model["use"]
                and grant["recipient_use"] == ctx.model["recipient_use"]
                and grant["report_destination"] == ctx.model["destination"],
                "model use differs from signed source grant")
    return notice, review_action


def _runtime_section(ctx, handoff):
    """The native configuration the handoff recorded, and its rule for the values section."""
    config_bytes = (ctx.root / ctx.model["runtime_config"]).read_bytes()
    require(sha(config_bytes) == ctx.model["runtime_config_sha256"]
            == handoff.record.body["details"]["runtime_config_sha256"],
            "native configuration differs from recorded handoff")
    config = json.loads(config_bytes)
    section = config["report_contract"]["section_rules"]["values"]
    require(section["required_attribution"] == handoff.notice and section["propagate_source_governance"] is True
            and all(section["required_tool"] == m["required_tool"] for m in handoff.declarations),
            "native gate does not carry the complete disclosure/compliance requirement")
    return runtime_limits_from_config(config), section


def _exchange(ctx, handoff):
    """The one retained exchange; its request carries the exact wire, use, and signed prompt."""
    lines = (ctx.root / "native-model/model-http.ndjson").read_text().splitlines()
    http = [entry for entry in map(json.loads, lines) if "body_b64" in entry]
    for entry in http:
        require(entry["body_sha256"] == "sha256:" + sha(base64.b64decode(entry["body_b64"], validate=True)),
                "HTTP transcript digest mismatch")
    requests = [e for e in http if e["direction"] == "request"]
    responses = [e for e in http if e["direction"] == "response"]
    require(len(requests) == len(responses) == 1, "expected one actual model exchange")
    request = json.loads(base64.b64decode(requests[0]["body_b64"]))
    source, dd = handoff.source, handoff.decision.body["details"]
    require(request["tn_object"].encode() == source.forward() and request["use"] == ctx.model["use"]
            and request["destination"] == ctx.model["destination"], "model transport changed native wire or use")
    require(len(dd["parameters"]) == 1
            and request["messages"] == [{"role": "user", "content": dd["parameters"][0]}],
            "model prompt differs from the signed Decision")
    request_digest = "sha256:" + sha(b"tn.llama.request.v2\0" + _canonical_bytes({
        "object_id": source.id, "use": request["use"], "destination": request["destination"],
        "messages": request["messages"],
    }))
    audit = [json.loads(line) for line in (ctx.root / "native-model/model-audit.ndjson").read_text().splitlines()]
    observations = {"record_kinds": [r["kind"] for r in audit],
                    "terminal_errors": [r["error_code"] for r in audit if r["kind"] == "terminal_error"],
                    "assurance": "local process observations; this execution log is not a signed remote attestation"}
    return Exchange(request, responses[0], request_digest, audit, observations)


def _failed_run(ctx, handoff, exchange, results):
    """A refused request has no success evidence and one signed endpoint failure."""
    response = exchange.response
    require(not results and response["status"] != 200, "failed model run has success evidence")
    error = json.loads(base64.b64decode(response["body_b64"]))["error"]["code"]
    failures = [r for r in ctx.records if r.body["kind"] == "Failure"
                and r.body["details"]["decision_id"] == handoff.decision.id]
    require(len(failures) == 1 and failures[0].body["details"]["native_code"] == error
            and ctx.model["output_object_id"] is None and not ctx.model["tool_object_ids"],
            "failed native request differs from signed endpoint failure")
    return {"completed": False, "http_status": response["status"], "input_object_id": handoff.source.id,
            "native_error": error, "native_observations": exchange.observations}


def _model_result(ctx, handoff, exchange, results):
    require(len(results) == 1 and exchange.response["status"] == 200,
            "completed model run lacks exact result/response")
    result = results[0]
    rd, hb = result.body["details"], handoff.record.body
    require(result.id == ctx.model["result_record_id"] and rd["handoff_record_id"] == handoff.record.id
            and result.body["sequence"] > hb["sequence"] and rd["input_object_id"] == handoff.source.id
            and rd["required_disclosure"] == handoff.notice and rd["claims"] == ctx.bindings[handoff.key]["claims"],
            "model result changed its source, conditions, or claim subjects")
    return result


def _release(ctx, handoff, exchange, result):
    """The release, its verified governance context, and retained bytes identical to the response."""
    body = base64.b64decode(exchange.response["body_b64"])
    release = NativeModelRelease.from_http_json(body)
    trace = [json.loads(line) for path in sorted((ctx.root / "native-model/model-traces").glob("*.ndjson"))
             for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    exchange.observations["governance_context"] = verified_context_observation(
        exchange.audit, trace, run_id=release.run_id, request_digest=exchange.request_digest,
        source_id=handoff.source.id, expected_release=json.loads(body), source_envelope=handoff.source.envelope,
        governance_hash_key=ctx.hash_key(ctx.resolve(handoff.key[0])),
    )
    rd = result.body["details"]
    require(release.output_object.id == ctx.model["output_object_id"] == rd["output_object_id"]
            and [o.id for o in release.tool_objects] == ctx.model["tool_object_ids"] == rd["tool_object_ids"]
            and len(release.tool_objects) == 1, "report or compliance identity differs from signed result")
    for obj in (release.output_object, *release.tool_objects):
        require(ctx.store.get(obj.id) == obj.forward(), "retained native release bytes differ from response")
    return release, trace


def _check_review(ctx, handoff, exchange, result, release, trace):
    """A required review is pending, signed, queued, and was shown to the model."""
    if handoff.review_action is None:
        return None
    review = _pending_review(ctx, handoff, result, release)
    notified = _review_notifications(exchange.audit, trace, release.run_id, handoff.notice)
    exchange.observations["review_notification_task_ids"] = notified
    exchange.observations["review_notice_in_model_prompt"] = bool(notified)
    require(bool(notified), "no native evidence that the model saw its review instruction")
    return review


def _pending_review(ctx, handoff, result, release):
    rd, hb = result.body["details"], handoff.record.body
    review_id = rd.get("review_request_id")
    record = ctx.by_id.get(review_id)
    require(record is not None and record.body["kind"] == "ReviewRequested",
            "generated report has no signed review request")
    vb, vd = record.body, record.body["details"]
    require(record.writer == result.writer and vb["call_id"] == hb["call_id"]
            and vb["context_id"] == hb["context_id"]
            and hb["sequence"] < vb["sequence"] < result.body["sequence"]
            and vd["decision_id"] == handoff.decision.id and vd["handoff_record_id"] == handoff.record.id,
            "review request is disconnected from the authorized handoff")
    require(vd["status"] == "pending" and vd["review_action"] == handoff.review_action
            and vd["input_object_id"] == handoff.source.id and vd["report_object_id"] == release.output_object.id
            and vd["required_disclosure"] == handoff.notice and vd["policy_revisions"] == sorted(handoff.revisions)
            and vd["report_html_sha256"] == rd["report_html_sha256"],
            "pending review changed its report, action, or source basis")
    action = handoff.review_action
    review = {"record_id": review_id, "report_object_id": release.output_object.id,
              "status": "pending", "assignee": action["assignee"], "reason": action["reason"],
              "queue_entry": "review-queue/" + review_id[7:] + ".tn"}
    require(ctx.model.get("review") == review and json.loads((ctx.root / "review.json").read_bytes()) == review,
            "review display differs from its signed pending request")
    require((ctx.root / review["queue_entry"]).read_bytes() == ctx.store.get(review_id),
            "pending queue does not contain the exact signed review request")
    return review


def _review_notifications(audit, trace, run_id, notice):
    """Authorized, completed, released turns whose rendered prompt carried the review notice."""
    authorized = {(r["run_id"], r["llama_task_id"], r["llama_slot_id"], json.loads(r["facts_json"]).get("phase"))
                  for r in audit if r["kind"] == "turn_begin_authorized"}

    def turn_key(r):
        return r["run_id"], r["task_id"], r["slot_id"], r["phase"]

    completed = {turn_key(r) for r in trace if r["kind"] == "model_result" and r.get("raw_model_output_b64")}
    released = {turn_key(r) for r in trace if r["kind"] == "release"}
    return [r["task_id"] for r in trace
            if r["run_id"] == run_id and r["kind"] == "turn_started"
            and turn_key(r) in authorized and turn_key(r) in completed
            and turn_key(r) in released and r.get("rendered_prompt_b64")
            and notice in base64.b64decode(r["rendered_prompt_b64"]).decode("utf-8")]


def _open_report(ctx, handoff, result, release, section, limits, request_digest):
    """Admit the report as the enrolled recipient; its visible text carries every original notice."""
    use = tn.UseContext(**ctx.model["recipient_use"])
    with tn.Session.from_config(str(ctx.root / ctx.model["recipient_config"])) as recipient:
        reader = NativeOutputReader(recipient, expected_source=handoff.source, expected_writer=ctx.model["writer"],
            use=use, destination=ctx.model["destination"], release_use=tn.UseContext(**ctx.model["use"]),
            catalog=ctx.catalog, policy_dag=ctx.dag, resolve_ancestor=ctx.resolve,
            decide=lambda admitted: admitted.use_context == use,
            expected_tool_name=section["required_tool"], expected_tool_sections=("values",),
            required_tools=(section["required_tool"],), expected_request_digest=request_digest,
            lineage_max_objects=limits["lineage_max_objects"],
            lineage_max_depth=limits["lineage_max_depth"])
        opened = reader.open(release)
        # This is independent artifact inspection after recipient admission. The
        # application release decision already happened in the native service.
        html = opened.get("report_html", group="default")
        require(sha(html.encode()) == result.body["details"]["report_html_sha256"]
                and (ctx.root / "report.html").read_bytes() == html.encode(),
                "display artifact differs from signed native report")
        visible = visible_text(html)
        require(all(" ".join(n.split()) in visible for n in handoff.notices),
                "required notice is absent from plain report text")
    return visible


def _native_edges(ctx, handoff, release, section):
    source_node_id = ctx.nodes[handoff.key]["id"]
    edges = [{"parent": source_node_id, "child": t.id, "operation": section["required_tool"]}
             for t in release.tool_objects]
    edges += [{"parent": source_node_id if obj.id == handoff.source.id else obj.id,
               "child": release.output_object.id, "operation": "generate_report"}
              for obj in (handoff.source, *release.tool_objects)]
    return edges
