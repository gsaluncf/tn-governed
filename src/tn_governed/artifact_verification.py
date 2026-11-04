"""Verify an artifact's manifest against its signed records, its parents, and its external inputs.

Each check is an application check on signed records; the endpoint's native session
admits and opens the publications. A cache belongs to one verification pass.
"""

from __future__ import annotations

from .artifact_types import MANIFEST_GROUP, GovernedArtifact, artifact_json, check_manifest
from .native_objects import include_carrier
from .values.evidence import EvidenceError
from .values.holders import field_hash, holds_field
from .values.references import unpack_references
from .values.runtime import Claim
from .values.string import ValueReference

_CALL_FIELDS = ("context_id", "call_id", "application", "purpose", "operation", "inputs", "destination")
_RELEASE_FIELDS = ("application", "purpose", "operation", "destination")


def verify_artifact(endpoint, artifact, cache=None, depth=0):
    """The artifact's admitted evidence, manifest, and claims, once every check holds."""
    if not isinstance(artifact, GovernedArtifact):
        raise TypeError("governed endpoint inputs require GovernedArtifact handles")
    if artifact.carrier is not None:
        include_carrier(endpoint.store, artifact.carrier)
    cache = {} if cache is None else cache
    if artifact in cache:
        return cache[artifact]
    if depth > 256:
        raise EvidenceError("artifact ancestry exceeds the verification depth limit")
    obj = endpoint.store.read(artifact.reference.object_id)
    data = endpoint.session.receive(obj, use=endpoint.inspect_use, groups=[MANIFEST_GROUP], decide=endpoint._admit)
    manifest = data.get("manifest", group=MANIFEST_GROUP)
    check_manifest(manifest, artifact.decision_id)
    parents = tuple(GovernedArtifact.from_dict(parent) for parent in manifest["parents"])
    external = tuple(ValueReference(**reference) for reference in manifest["external_inputs"])
    view = endpoint.session.governance(obj)
    inputs = [parent.reference.to_dict() for parent in parents] + [item.to_dict() for item in external]
    decision = _check_operation_records(endpoint, artifact, obj, view, manifest, inputs)
    _check_required_actions(endpoint, decision)
    claims = _read_claims(endpoint, manifest)
    _check_disputes_and_actions(endpoint, artifact, manifest)
    inherited = _parent_policies(endpoint, parents, manifest, cache, depth) + _external_policies(endpoint, external)
    _check_policy_union(inherited, data.policies)
    direct = {item.reference.object_id for item in parents} | {item.object_id for item in external}
    if not direct <= {source.object_id for source in view.governance.sources}:
        raise EvidenceError("artifact native provenance omits a direct input")
    cache[artifact] = data, artifact_json(manifest), tuple(claims)
    return cache[artifact]


def _check_operation_records(endpoint, artifact, obj, view, manifest, inputs):
    """The Decision and Result agree with the manifest, the native commitments, and each other."""
    decision, result = endpoint._record(artifact.decision_id), endpoint._record(artifact.result_id)
    db, rb = decision.body, result.body
    if (
        decision.writer != obj.writer
        or result.writer != obj.writer
        or db["kind"] != "Decision"
        or db["details"].get("permitted") is not True
        or rb["kind"] != "Result"
        or rb["details"].get("output") != artifact.reference.to_dict()
        or rb["details"].get("decision_id") != artifact.decision_id
        or rb["details"].get("manifest_commitment") != field_hash(obj, MANIFEST_GROUP, "manifest")
        or rb["details"].get("value_commitment") != field_hash(obj, "values", "value")
        or db["operation"] != manifest["operation"]
        or db["details"].get("parameters") != manifest["parameters"]
        or db["destination"] != manifest["destination"]
        or unpack_references(db["inputs"]) != inputs
        or rb["sequence"] <= db["sequence"]
        or any(rb[key] != db[key] for key in _CALL_FIELDS)
        or view.governance.fields.get("release_context") != {key: db[key] for key in _RELEASE_FIELDS}
    ):
        raise EvidenceError("artifact does not match its signed decision and result")
    return decision


def _check_required_actions(endpoint, decision):
    """Each discharged obligation has its signed required-action observation before the Decision."""
    db = decision.body
    progress, discharged = db["details"].get("action_progress"), db["details"].get("discharged")
    if (
        not isinstance(progress, list)
        or not isinstance(discharged, list)
        or len(progress) != len(discharged)
        or [step.get("obligation") for step in discharged] != db["details"].get("obligations")
        or any(step.get("satisfied") is not True for step in discharged)
    ):
        raise EvidenceError("artifact decision has incomplete required-action evidence")
    for index, (identity, step) in enumerate(zip(progress, discharged, strict=True)):
        observation = endpoint._record(identity)
        body = observation.body
        if (
            observation.writer != decision.writer
            or body["kind"] != "Observation"
            or body["details"] != {"stage": "required-action", "index": index, **step}
            or body["sequence"] >= db["sequence"]
            or any(body[key] != db[key] for key in _CALL_FIELDS)
        ):
            raise EvidenceError("required-action progress differs from the signed decision")


def _read_claims(endpoint, manifest):
    claims = []
    for identity in manifest["claims"]:
        record = endpoint._record(identity)
        if record.body["kind"] != "Claim" or not isinstance(record.body["details"].get("statement"), str):
            raise EvidenceError("artifact claim reference is invalid")
        subjects = tuple(ValueReference(**value) for value in unpack_references(record.body["inputs"]))
        claims.append(Claim(record.id, record.writer, subjects, record.body["details"]["statement"]))
    return claims


def _check_disputes_and_actions(endpoint, artifact, manifest):
    for dispute in manifest["disputes"]:
        if (
            set(dispute) != {"claim_id", "dispute_id"}
            or not {dispute["claim_id"], dispute["dispute_id"]} <= set(manifest["claims"])
            or endpoint._record(dispute["dispute_id"]).body["details"].get("disputes") != dispute["claim_id"]
        ):
            raise EvidenceError("artifact dispute is not bound to its original claim")
    for identity in manifest["action_records"]:
        if endpoint._record(identity).body["kind"] != "Decision":
            raise EvidenceError("action evidence must reference signed decisions")
    if artifact.decision_id not in manifest["action_records"]:
        raise EvidenceError("artifact omits its producing action decision")


def _parent_policies(endpoint, parents, manifest, cache, depth):
    """Verify each parent; the artifact keeps its claims, actions, and disputes. Return their policies."""
    inherited = []
    for parent in parents:
        parent_data, parent_manifest, _ = verify_artifact(endpoint, parent, cache, depth + 1)
        inherited.extend(parent_data.policies)
        if (
            not set(parent_manifest["claims"]) <= set(manifest["claims"])
            or not set(parent_manifest["action_records"]) <= set(manifest["action_records"])
            or any(dispute not in manifest["disputes"] for dispute in parent_manifest["disputes"])
        ):
            raise EvidenceError("artifact omits contributing claims or completed-action evidence")
    return inherited


def _external_policies(endpoint, external):
    """Admit each external input's group; return the policies its admitted route carries."""
    inherited = []
    for reference in external:
        source = endpoint.store.read(reference.object_id)
        # Native admission asks the source and each object on the path to the group's
        # holder; the admitted route holds the policies a received copy holds.
        inherited.extend(endpoint.session.admit(source, use=endpoint.inspect_use, groups=[reference.group],
                                                decide=endpoint.accept_metadata).policies)
        if not holds_field(source, reference.group, reference.field):
            raise EvidenceError("external input does not identify a signed field")
    return inherited


def _check_policy_union(inherited, policies):
    if inherited and (
        not all(any(policy.matches_contract(other) for other in policies) for policy in inherited)
        or not all(any(policy.matches_contract(other) for other in inherited) for policy in policies)
    ):
        raise EvidenceError("artifact does not preserve its contributing policy union")


def external_claims(endpoint, publication, identities, limit=10000):
    """The signed Claims an import carries; each subject is a signed field of the publication's ancestry."""
    lineage = _external_lineage(endpoint, publication, limit) if identities else {}
    claims = []
    for identity in identities:
        record = endpoint._record(identity)
        if record.body["kind"] != "Claim" or not isinstance(record.body["details"].get("statement"), str):
            raise EvidenceError("external claim reference is not a claim")
        subjects = tuple(ValueReference(**item) for item in unpack_references(record.body["inputs"]))
        if not subjects or any(
            subject.object_id not in lineage
            or not holds_field(lineage[subject.object_id], subject.group, subject.field)
            for subject in subjects
        ):
            raise EvidenceError("external claim subject is not a contributing signed field")
        claims.append(Claim(record.id, record.writer, subjects, record.body["details"]["statement"]))
    return claims


def _external_lineage(endpoint, publication, limit):
    lineage, pending = {}, [publication.id]
    while pending:
        identity = pending.pop()
        if identity in lineage:
            continue
        if len(lineage) >= limit:
            raise EvidenceError("external ancestry exceeds the configured object limit")
        ancestor = endpoint.store.read(identity)
        lineage[identity] = ancestor
        pending.extend(source.object_id for source in endpoint.session.governance(ancestor).governance.sources)
    return lineage
