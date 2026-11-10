"""Check the carried rules, claims, and action records of a signed publication."""

from __future__ import annotations

from .artifact_types import MANIFEST_GROUP, GovernedArtifact, artifact_json, check_manifest
from .native_objects import include_carrier
from .values.evidence import OBJECT_ID, EvidenceError, check_monitor
from .values.holders import field_hash, holds_field
from .values.manifests import POLICY_SCHEMA, SCHEMAS, signed_manifest
from .values.references import unpack_references
from .values.runtime import Claim
from .values.string import ValueReference

_CALL_FIELDS = ("context_id", "call_id", "application", "purpose", "operation", "inputs", "destination")
_RELEASE_FIELDS = ("application", "purpose", "operation", "destination")


def verify_artifact(endpoint, artifact, cache=None):
    """The artifact's admitted evidence, manifest, and claims, once every check holds."""
    if not isinstance(artifact, GovernedArtifact):
        raise TypeError("governed endpoint inputs require GovernedArtifact handles")
    if artifact.carrier is not None:
        include_carrier(endpoint.store, artifact.carrier)
    cache = {} if cache is None else cache
    if artifact in cache:
        return cache[artifact]
    obj = endpoint.store.read(artifact.reference.object_id)
    data = endpoint.session.receive(obj, use=endpoint.inspect_use, groups=[MANIFEST_GROUP], decide=endpoint._admit)
    manifest = data.get("manifest", group=MANIFEST_GROUP)
    check_manifest(manifest, artifact.decision_id)
    if not holds_field(obj, artifact.reference.group, artifact.reference.field):
        raise EvidenceError("artifact value is absent from the signed publication")
    if artifact.decision_id:
        _check_operation_records(endpoint, artifact, obj, endpoint.session.governance(obj), manifest)
    claims = _read_claims(endpoint, manifest)
    _check_disputes_and_actions(endpoint, artifact, manifest)
    cache[artifact] = data, artifact_json(manifest), tuple(claims)
    return cache[artifact]


def _check_operation_records(endpoint, artifact, obj, view, manifest):
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
        not isinstance(discharged, list)
        or (progress is not None and (not isinstance(progress, list) or len(progress) != len(discharged)))
        or [step.get("obligation") for step in discharged] != db["details"].get("obligations")
        or any(step.get("satisfied") is not True or not isinstance(step.get("evidence"), str)
               or not step["evidence"].strip() for step in discharged)
    ):
        raise EvidenceError("artifact decision has incomplete required-action evidence")
    if progress is None:
        for step in discharged:
            if OBJECT_ID.fullmatch(step["evidence"]):
                receipt = endpoint._record(step["evidence"])
                if step["obligation"] == "monitor":
                    check_monitor(decision, receipt)
            elif step["obligation"] == "monitor":
                raise EvidenceError("monitoring requires a signed receipt")
        return
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
        decision = endpoint._record(identity)
        if decision.body["kind"] != "Decision" or decision.body["details"].get("permitted") is not True:
            raise EvidenceError("action evidence must reference signed decisions")
        _check_required_actions(endpoint, decision)
    if artifact.decision_id and artifact.decision_id not in manifest["action_records"]:
        raise EvidenceError("artifact omits its producing action decision")


def external_claims(endpoint, publication, reference, identities, bound_claims):
    """Accept claims named by the field's signed manifest or made about this field directly."""
    claims = _read_claims(endpoint, {"claims": identities})
    for claim in claims:
        if claim.id not in bound_claims and (reference not in claim.subjects or
                not holds_field(publication, reference.group, reference.field)):
            raise EvidenceError("external claim subject is not bound to the imported field")
    return claims


def imported_field_evidence(endpoint, data, metadata_group, group, field):
    fields = data.get(group=metadata_group)
    frame = fields.get("tn_polars_governance")
    manifest = fields.get("manifest")
    if frame is not None:
        if (frame.get("schema"), frame.get("group"), frame.get("rows_field")) != (
            "tn.polars-governance.v2", group, field
        ):
            raise EvidenceError("frame governance does not describe the imported field")
        binding = frame
    elif isinstance(manifest, dict) and manifest.get("schema") == "tn.governed-fields.v1":
        binding = manifest["bindings"].get(field)
        if not isinstance(binding, dict) or binding.get("group") != group:
            raise EvidenceError("no governance binding for the imported field")
    elif isinstance(manifest, dict) and manifest.get("schema") == "tn.sql-result.v2":
        if (group, field) != ("values", "rows"):
            raise EvidenceError("SQL governance does not describe the imported field")
        binding = {"claims": [], "actions": manifest["actions"]}
    elif isinstance(manifest, dict) and manifest.get("schema") in SCHEMAS:
        if metadata_group != MANIFEST_GROUP or group != "values":
            raise EvidenceError("primitive governance does not describe the imported group")
        binding = signed_manifest(data)["bindings"].get(field)
        if binding is None:
            raise EvidenceError("no governance binding for the imported field")
        if manifest["schema"] != POLICY_SCHEMA:
            decision = endpoint._record(binding["decision_id"])
            binding = {**binding, "actions": [decision.id] if decision.body["details"].get("obligations") else []}
    else:
        return (), ()
    claims, actions = binding["claims"], binding["actions"]
    if not all(isinstance(ids, list) and all(isinstance(i, str) for i in ids) for ids in (claims, actions)):
        raise EvidenceError("invalid evidence on the imported field")
    for identity in actions:
        decision = endpoint._record(identity)
        if decision.body["kind"] != "Decision" or decision.body["details"].get("permitted") is not True:
            raise EvidenceError("import requires signed action decisions")
        _check_required_actions(endpoint, decision)
    return claims, actions
