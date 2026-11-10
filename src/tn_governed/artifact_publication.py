"""Publish an operation's output as a native artifact with its signed manifest and Result."""

from __future__ import annotations

import json

import tn

from .artifact_transfer import carried
from .artifact_types import ARTIFACT_SCHEMA, ARTIFACT_TYPE, MANIFEST_GROUP, GovernedArtifact, artifact_json
from .values.holders import field_hash
from .values.string import ValueReference


def publish_artifact(endpoint, value, metadata, opened, request, decision, call_id, *,
                     claim=None, dispute=None, state="active", actions=()):
    """Release `value` with its manifest under the request's policies; return the carried artifact."""
    value = artifact_json(value)
    data = _working_copy(endpoint, opened, request)
    claims, disputes = _artifact_claims(endpoint, request, metadata, call_id, claim, dispute)
    action_records = list(dict.fromkeys([
        *(identity for _, manifest, _ in metadata for identity in manifest["action_records"]),
        *actions, *((decision,) if decision else ())]))
    manifest = {
        "schema": ARTIFACT_SCHEMA,
        "operation": request.operation,
        "parameters": request.parameters[0],
        "destination": request.destination,
        "decision_id": decision,
        "claims": claims,
        "disputes": list({json.dumps(item, sort_keys=True): item for item in disputes}.values()),
        "action_records": action_records,
        "state": state,
    }
    publication = _release(endpoint, data, value, manifest, request)
    reference = ValueReference(publication.id, "value", "values")
    result = None if decision is None else endpoint._append("Result", request, call_id, {
        "decision_id": decision,
        "output": reference.to_dict(),
        "claims": claims,
        "manifest_commitment": field_hash(publication, MANIFEST_GROUP, "manifest"),
        "value_commitment": field_hash(publication, "values", "value"),
    })
    return carried(endpoint, GovernedArtifact(reference, decision, result), manifest=manifest)


def _working_copy(endpoint, opened, request):
    """Copy the opened inputs together, or originate an empty copy under every requested policy."""
    if opened:
        return opened[0].policy_output(ARTIFACT_TYPE, {"values": {}}, inputs=opened[1:])
    data = endpoint.session.create({}, request.policies[0], object_type=ARTIFACT_TYPE, group="values")
    endpoint.store.put(data.snapshot)
    for policy in request.policies[1:]:
        data.attach(policy, decide=lambda ctx, policy=policy: ctx.policy.matches_contract(policy))
    return data.policy_output(ARTIFACT_TYPE, {"values": {}})


def _artifact_claims(endpoint, request, metadata, call_id, claim, dispute):
    """Every contributing claim and dispute, plus a claim or dispute this operation signs."""
    claims = list(dict.fromkeys([
        *(item.id for item in request.claims),
        *(identity for _, manifest, _ in metadata for identity in manifest["claims"]),
    ]))
    disputes = [item for _, manifest, _ in metadata for item in manifest["disputes"]]
    if claim is None:
        return claims, disputes
    details = {"statement": claim}
    if dispute is not None:
        if dispute not in claims:
            raise ValueError("a dispute must identify a retained claim")
        details["disputes"] = dispute
    identity = endpoint._append("Claim", request, call_id, details)
    claims.append(identity)
    if dispute is not None:
        disputes.append({"claim_id": dispute, "dispute_id": identity})
    return claims, disputes


def _release(endpoint, data, value, manifest, request):
    """Write both groups, designate the manifest, and release under exactly the request's policies."""
    data.set(None, {"value": value}, group="values")
    data.set(None, {"manifest": manifest}, group=MANIFEST_GROUP)
    data.bind_manifest(MANIFEST_GROUP)
    data.select(["values", MANIFEST_GROUP])
    expected = request.policies

    def release(ctx):
        return (
            ctx.writer == endpoint.session.did
            and len(ctx.policies) == len(expected)
            and all(any(p.matches_contract(q) for q in expected) for p in ctx.policies)
        )

    publication = data.release(
        use=tn.UseContext(endpoint.application, endpoint.purpose, manifest["operation"]),
        to=request.destination,
        object_type=ARTIFACT_TYPE,
        decide=release,
    )
    endpoint.store.put(publication)
    return publication
