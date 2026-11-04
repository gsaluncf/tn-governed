"""Locally authorized operations over portable native TN artifacts."""

from __future__ import annotations

import json
import math
import threading
from dataclasses import dataclass, field, replace
from uuid import uuid4

import tn

from .native_objects import CarriedPublication, NativeObjects
from .values.evidence import EvidenceError, EvidenceRecorder, read_record
from .values.obligations import ObligationRun, run_obligations
from .values.references import unpack_references
from .values.runtime import Assessment, Claim, Request
from .values.string import OperationDenied, ValueReference
from .values.holders import field_hash, holder, receive_routed

ARTIFACT_TYPE = "tn.artifact"
ARTIFACT_SCHEMA = "tn.artifact.v1"


def _json(value, depth=0):
    if depth > 128:
        raise ValueError("JSON nesting exceeds the artifact limit")
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    if type(value) in (list, tuple):
        return [_json(item, depth + 1) for item in value]
    if type(value) is dict and all(type(key) is str for key in value):
        return {key: _json(item, depth + 1) for key, item in value.items()}
    raise TypeError("artifact data requires ordinary finite JSON values with string keys")


@dataclass(frozen=True)
class GovernedArtifact:
    reference: ValueReference
    decision_id: str
    result_id: str
    carrier: CarriedPublication | None = field(default=None, compare=False, hash=False, repr=False)

    def __post_init__(self):
        from .publications import object_digest

        if not isinstance(self.reference, ValueReference):
            raise TypeError("an artifact requires a native value reference")
        if self.reference.group != "values" or self.reference.field != "value":
            raise ValueError("artifact references must select values.value")
        object_digest(self.decision_id)
        object_digest(self.result_id)
        if self.carrier is not None and (
            not isinstance(self.carrier, CarriedPublication)
            or self.carrier.object.id != self.reference.object_id
        ):
            raise ValueError("artifact carrier must contain its native publication")

    def to_dict(self):
        return {
            "reference": self.reference.to_dict(),
            "decision_id": self.decision_id,
            "result_id": self.result_id,
        }

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict) or set(value) != {"reference", "decision_id", "result_id"}:
            raise EvidenceError("invalid governed artifact handle")
        return cls(ValueReference(**value["reference"]), value["decision_id"], value["result_id"])


@dataclass(frozen=True)
class ArtifactBundle:
    artifact: GovernedArtifact
    publications: tuple[bytes, ...]


class Endpoint:
    """A native session, local authority configuration, and signed operation recorder.

    A lock serializes one endpoint's native session and record chain. Endpoints
    with separate sessions and stores can decide and execute concurrently.
    Callbacks run inside the authorized boundary and must return ordinary JSON.
    """

    def __init__(
        self,
        *,
        session,
        store=None,
        evidence_policy,
        evaluator,
        application,
        purpose,
        accept_metadata,
        evidence_policies=(),
        obligations=None,
    ):
        if not all(callable(callback) for callback in (evaluator, accept_metadata)):
            raise TypeError("endpoint requires authority and operation evaluators")
        self.session, self.store = session, NativeObjects() if store is None else store
        self.application, self.purpose = application, purpose
        self.evaluator, self.accept_metadata = evaluator, accept_metadata
        self.evidence_policies = tuple(evidence_policies) + (evidence_policy,)
        self.recorder = EvidenceRecorder(session, self.store, evidence_policy)
        self.obligations = dict(obligations or {})
        self._lock = threading.RLock()

    def _record(self, identity):
        obj = self.store.read(identity)
        actual = self.session.governance(obj)
        for policy in self.evidence_policies:
            if actual.governance.matches_contract(policy):
                return read_record(obj, session=self.session, policy=policy)
        raise EvidenceError("evidence contract is not accepted by this endpoint")

    def records(self):
        with self._lock:
            return tuple(
                self._record(tn.GovernedObject.parse(wire).id) for wire in self.recorder.records()
            )

    def read_record(self, identity):
        with self._lock:
            return self._record(identity)

    def _append(self, kind, request, call_id, details):
        return self.recorder.append(
            kind,
            call_id=call_id,
            application=request.application,
            purpose=request.purpose,
            operation=request.operation,
            inputs=request.inputs,
            destination=request.destination,
            details=details,
        )

    def _admit(self, context):
        return (
            context.object_type == ARTIFACT_TYPE
            and bool(context.policies)
            and self.accept_metadata(context) is True
        )

    def _metadata(self, artifact, _cache=None, _depth=0):
        if not isinstance(artifact, GovernedArtifact):
            raise TypeError("governed endpoint inputs require GovernedArtifact handles")
        if artifact.carrier is not None:
            self._include(artifact.carrier)
        cache = {} if _cache is None else _cache
        if artifact in cache:
            return cache[artifact]
        if _depth > 256:
            raise EvidenceError("artifact ancestry exceeds the verification depth limit")
        obj = self.store.read(artifact.reference.object_id)
        data = self.session.receive(
            obj,
            use=tn.UseContext(self.application, self.purpose, "inspect"),
            groups=["evidence"],
            decide=self._admit,
        )
        manifest = data.get("manifest", group="evidence")
        fields = {
            "schema",
            "operation",
            "parameters",
            "destination",
            "decision_id",
            "parents",
            "claims",
            "disputes",
            "action_records",
            "state",
            "external_inputs",
        }
        if (
            not isinstance(manifest, dict)
            or set(manifest) != fields
            or manifest["schema"] != ARTIFACT_SCHEMA
            or manifest["decision_id"] != artifact.decision_id
            or manifest["state"] not in {"active", "deleted"}
            or not isinstance(manifest["parameters"], dict)
            or any(
                not isinstance(manifest[key], list)
                for key in ("parents", "claims", "disputes", "action_records", "external_inputs")
            )
        ):
            raise EvidenceError("artifact manifest is invalid")
        parents = tuple(GovernedArtifact.from_dict(parent) for parent in manifest["parents"])
        external = tuple(ValueReference(**reference) for reference in manifest["external_inputs"])
        decision, result = self._record(artifact.decision_id), self._record(artifact.result_id)
        db, rb = decision.body, result.body
        release_context = self.session.governance(obj).governance.fields.get("release_context")
        if (
            decision.writer != obj.writer
            or result.writer != obj.writer
            or db["kind"] != "Decision"
            or db["details"].get("permitted") is not True
            or rb["kind"] != "Result"
            or rb["details"].get("output") != artifact.reference.to_dict()
            or rb["details"].get("decision_id") != artifact.decision_id
            or rb["details"].get("manifest_commitment")
            != field_hash(obj, "evidence", "manifest")
            or rb["details"].get("value_commitment")
            != field_hash(obj, "values", "value")
            or db["operation"] != manifest["operation"]
            or db["details"].get("parameters") != manifest["parameters"]
            or db["destination"] != manifest["destination"]
            or db["inputs"]
            != [parent.reference.to_dict() for parent in parents]
            + [item.to_dict() for item in external]
            or rb["sequence"] <= db["sequence"]
            or any(
                rb[key] != db[key]
                for key in (
                    "context_id",
                    "call_id",
                    "application",
                    "purpose",
                    "operation",
                    "inputs",
                    "destination",
                )
            )
            or release_context
            != {key: db[key] for key in ("application", "purpose", "operation", "destination")}
        ):
            raise EvidenceError("artifact does not match its signed decision and result")
        progress = db["details"].get("action_progress")
        discharged = db["details"].get("discharged")
        if (
            not isinstance(progress, list)
            or not isinstance(discharged, list)
            or len(progress) != len(discharged)
            or [step.get("obligation") for step in discharged] != db["details"].get("obligations")
            or any(step.get("satisfied") is not True for step in discharged)
        ):
            raise EvidenceError("artifact decision has incomplete required-action evidence")
        for index, (identity, step) in enumerate(zip(progress, discharged, strict=True)):
            observation = self._record(identity)
            body = observation.body
            if (
                observation.writer != decision.writer
                or body["kind"] != "Observation"
                or body["details"] != {"stage": "required-action", "index": index, **step}
                or body["sequence"] >= db["sequence"]
                or any(
                    body[key] != db[key]
                    for key in (
                        "context_id",
                        "call_id",
                        "application",
                        "purpose",
                        "operation",
                        "inputs",
                        "destination",
                    )
                )
            ):
                raise EvidenceError("required-action progress differs from the signed decision")
        claims = []
        for identity in manifest["claims"]:
            record = self._record(identity)
            if record.body["kind"] != "Claim" or not isinstance(
                record.body["details"].get("statement"), str
            ):
                raise EvidenceError("artifact claim reference is invalid")
            claims.append(
                Claim(
                    record.id,
                    record.writer,
                    tuple(ValueReference(**value) for value in unpack_references(record.body["inputs"])),
                    record.body["details"]["statement"],
                )
            )
        for dispute in manifest["disputes"]:
            if (
                set(dispute) != {"claim_id", "dispute_id"}
                or not {dispute["claim_id"], dispute["dispute_id"]} <= set(manifest["claims"])
                or self._record(dispute["dispute_id"]).body["details"].get("disputes")
                != dispute["claim_id"]
            ):
                raise EvidenceError("artifact dispute is not bound to its original claim")
        for identity in manifest["action_records"]:
            if self._record(identity).body["kind"] != "Decision":
                raise EvidenceError("action evidence must reference signed decisions")
        if artifact.decision_id not in manifest["action_records"]:
            raise EvidenceError("artifact omits its producing action decision")
        inherited = []
        for parent in parents:
            parent_data, parent_manifest, _ = self._metadata(parent, cache, _depth + 1)
            inherited.extend(parent_data.policies)
            if (
                not set(parent_manifest["claims"]) <= set(manifest["claims"])
                or not set(parent_manifest["action_records"]) <= set(manifest["action_records"])
                or any(
                    dispute not in manifest["disputes"] for dispute in parent_manifest["disputes"]
                )
            ):
                raise EvidenceError(
                    "artifact omits contributing claims or completed-action evidence"
                )
        for reference in external:
            source = self.store.read(reference.object_id)
            view = self.session.governance(source)
            # A carried group is admitted on the governance of the object that holds it.
            held = view if reference.group in source.group_names else self.session.governance(
                holder(source, reference.group))
            held.accept(
                use=tn.UseContext(self.application, self.purpose, "inspect"),
                groups=[reference.group],
                decide=self.accept_metadata,
            )
            if reference.field not in holder(source, reference.group).envelope[reference.group]["field_hashes"]:
                raise EvidenceError("external input does not identify a signed field")
            inherited.extend(view.governance.policies)
        if inherited and (
            not all(
                any(policy.matches_contract(other) for other in data.policies)
                for policy in inherited
            )
            or not all(
                any(policy.matches_contract(other) for other in inherited)
                for policy in data.policies
            )
        ):
            raise EvidenceError("artifact does not preserve its contributing policy union")
        if not {parent.reference.object_id for parent in parents} | {
            item.object_id for item in external
        } <= {source.object_id for source in self.session.governance(obj).governance.sources}:
            raise EvidenceError("artifact native provenance omits a direct input")
        cache[artifact] = data, _json(manifest), tuple(claims)
        return cache[artifact]

    def metadata(self, artifact):
        with self._lock:
            return self._metadata(artifact)[1]

    def claims(self, artifact):
        with self._lock:
            return self._metadata(artifact)[2]

    def _request(self, operation, inputs, parameters, destination, policies=(), metadata_only=()):
        if not isinstance(operation, str) or not operation.strip():
            raise ValueError("operation requires a nonempty name")
        if not isinstance(destination, str) or not destination.strip():
            raise ValueError("operation requires a named destination")
        if not isinstance(parameters, dict):
            raise TypeError("operation parameters require a JSON object")
        metadata = tuple(self._metadata(value) for value in inputs)
        if any(
            item[1]["state"] != "active" and value not in metadata_only
            for value, item in zip(inputs, metadata, strict=True)
        ):
            raise OperationDenied("a deleted version cannot be used as an active input")
        contracts = {}
        for policy in (*policies, *(policy for data, _, _ in metadata for policy in data.policies)):
            key = (policy.governed_by, policy.policy_ref, policy.revision_id)
            if key in contracts and not contracts[key].matches_contract(policy):
                raise EvidenceError("conflicting representations of a source contract")
            contracts[key] = policy
        if not contracts:
            raise OperationDenied("a governed artifact requires source governance")
        claims = {claim.id: claim for _, _, claims in metadata for claim in claims}
        request = Request(
            self.application,
            self.purpose,
            operation,
            tuple(value.reference for value in inputs),
            tuple(data.snapshot.writer for data, _, _ in metadata),
            tuple(contracts.values()),
            tuple(claims.values()),
            destination,
            (_json(parameters),),
        )
        return request, metadata

    def _authorize(self, request, call_id):
        actions, cause = ObligationRun(), None
        progress = []
        details = {"parameters": request.parameters[0], "action_progress": progress}

        def observe(step):
            identity = self._append(
                "Observation",
                request,
                call_id,
                {
                    "stage": "required-action",
                    "index": len(progress),
                    "obligation": step.name,
                    "satisfied": step.satisfied,
                    "evidence": step.evidence,
                },
            )
            progress.append(identity)

        try:
            assessment = self.evaluator(request)
            if (
                not isinstance(assessment, Assessment)
                or type(assessment.permit) is not bool
                or not isinstance(assessment.reason, str)
            ):
                raise TypeError("evaluator must return an explicit Assessment")
            permitted = assessment.permit
            if permitted:
                actions = run_obligations(
                    request, assessment.obligations, self.obligations, observe=observe
                )
                permitted, cause = actions.complete, actions.error
            details.update(
                permitted=permitted,
                requested_permit=assessment.permit,
                reason=assessment.reason,
                obligations=list(assessment.obligations),
                claim_judgments=[list(item) for item in assessment.claim_judgments],
                policies=[
                    {"authority": p.governed_by, "policy": p.policy_ref, "revision": p.revision_id}
                    for p in request.policies
                ],
                **actions.record_details(),
            )
            if hasattr(assessment, "evaluation"):
                details["evaluation"] = _json(assessment.evaluation)
        except Exception as exc:
            permitted, cause = False, exc
            details.update(
                {
                    **actions.record_details(),
                    "permitted": False,
                    "reason": "decision could not be completed",
                    "error_type": type(exc).__name__,
                }
            )
        decision = self._append("Decision", request, call_id, details)
        if not permitted:
            self._append(
                "Refusal", request, call_id, {"decision_id": decision, "reason": details["reason"]}
            )
            raise OperationDenied(f"{request.operation} refused; decision {decision}") from cause
        return decision

    def _open(self, artifact, request):
        data = self.session.receive(
            self.store.read(artifact.reference.object_id),
            use=tn.UseContext(request.application, request.purpose, request.operation),
            groups=["values", "evidence"],
            decide=self._admit,
        )
        return data, _json(data.get("value", group="values"))

    def _publish(
        self,
        value,
        inputs,
        metadata,
        opened,
        request,
        decision,
        call_id,
        *,
        claim=None,
        dispute=None,
        state="active",
        external_inputs=(),
    ):
        value = _json(value)
        if opened:
            data = opened[0].copy()
            data.include_all(opened[1:])
        else:
            data = self.session.create(
                {}, request.policies[0], object_type=ARTIFACT_TYPE, group="values"
            )
            self.store.put(data.snapshot)
            for policy in request.policies[1:]:
                data.attach(
                    policy, decide=lambda ctx, policy=policy: ctx.policy.matches_contract(policy)
                )
        claims = list(
            dict.fromkeys(
                [
                    *(claim.id for claim in request.claims),
                    *(identity for _, manifest, _ in metadata for identity in manifest["claims"]),
                ]
            )
        )
        disputes = [item for _, manifest, _ in metadata for item in manifest["disputes"]]
        if claim is not None:
            details = {"statement": claim}
            if dispute is not None:
                if dispute not in claims:
                    raise ValueError("a dispute must identify a retained claim")
                details["disputes"] = dispute
            identity = self._append("Claim", request, call_id, details)
            claims.append(identity)
            if dispute is not None:
                disputes.append({"claim_id": dispute, "dispute_id": identity})
        action_records = list(
            dict.fromkeys(
                [
                    *(
                        identity
                        for _, manifest, _ in metadata
                        for identity in manifest["action_records"]
                    ),
                    decision,
                ]
            )
        )
        manifest = {
            "schema": ARTIFACT_SCHEMA,
            "operation": request.operation,
            "parameters": request.parameters[0],
            "destination": request.destination,
            "decision_id": decision,
            "parents": [value.to_dict() for value in inputs],
            "claims": claims,
            "disputes": list(
                {json.dumps(item, sort_keys=True): item for item in disputes}.values()
            ),
            "action_records": action_records,
            "state": state,
            "external_inputs": [reference.to_dict() for reference in external_inputs],
        }
        data.set(None, {"value": value}, group="values")
        data.set(None, {"manifest": manifest}, group="evidence")
        data.select(["values", "evidence"])
        expected = request.policies

        def release(ctx):
            return (
                ctx.writer == self.session.did
                and len(ctx.policies) == len(expected)
                and all(any(p.matches_contract(q) for q in expected) for p in ctx.policies)
            )

        publication = data.release(
            use=tn.UseContext(self.application, self.purpose, request.operation),
            to=request.destination,
            object_type=ARTIFACT_TYPE,
            decide=release,
        )
        self.store.put(publication)
        reference = ValueReference(publication.id, "value", "values")
        result = self._append(
            "Result",
            request,
            call_id,
            {
                "decision_id": decision,
                "output": reference.to_dict(),
                "claims": claims,
                "manifest_commitment": field_hash(publication, "evidence", "manifest"),
                "value_commitment": field_hash(publication, "values", "value"),
            },
        )
        return self._carried(
            GovernedArtifact(reference, decision, result),
            parents=inputs,
            manifest=manifest,
            parent_metadata=metadata,
        )

    def _execute(
        self,
        operation,
        inputs,
        compute,
        parameters,
        destination,
        *,
        policies=(),
        claim=None,
        dispute=None,
        state="active",
        open_values=True,
        metadata_only=(),
    ):
        inputs = tuple(inputs)
        with self._lock:
            request, metadata = self._request(
                operation, inputs, _json(parameters or {}), destination, policies, metadata_only
            )
            call_id = uuid4().hex
            decision = self._authorize(request, call_id)
            try:
                pairs = (
                    tuple(
                        (metadata[index][0], None)
                        if value in metadata_only
                        else self._open(value, request)
                        for index, value in enumerate(inputs)
                    )
                    if open_values
                    else ()
                )
                value = compute(tuple(value for _, value in pairs))
                opened = (
                    tuple(data for data, _ in pairs)
                    if open_values
                    else tuple(item[0] for item in metadata)
                )
                return self._publish(
                    value,
                    inputs,
                    metadata,
                    opened,
                    request,
                    decision,
                    call_id,
                    claim=claim,
                    dispute=dispute,
                    state=state,
                )
            except Exception as exc:
                self._append(
                    "Failure",
                    request,
                    call_id,
                    {"decision_id": decision, "error_type": type(exc).__name__},
                )
                raise

    def originate(self, value, *, policies, operation="originate", parameters=None):
        return self._execute(
            operation, (), lambda _: value, parameters, "governed-runtime", policies=tuple(policies)
        )

    def execute(
        self, operation, inputs, compute, *, parameters=None, destination="governed-runtime"
    ):
        if not callable(compute):
            raise TypeError("operation requires an authorized computation callback")
        return self._execute(operation, inputs, compute, parameters, destination)

    def attest(self, artifact, statement):
        if not isinstance(statement, str) or not statement.strip():
            raise ValueError("claim requires a nonempty statement")
        return self._execute(
            "attest",
            (artifact,),
            lambda values: values[0],
            {"statement": statement},
            "governed-runtime",
            claim=statement,
        )

    def dispute(self, artifact, claim_id, statement):
        if not isinstance(statement, str) or not statement.strip():
            raise ValueError("dispute requires a nonempty statement")
        return self._execute(
            "dispute",
            (artifact,),
            lambda values: values[0],
            {"claim_id": claim_id, "statement": statement},
            "governed-runtime",
            claim=statement,
            dispute=claim_id,
        )

    def retire(self, artifact, *, parameters=None):
        return self._execute(
            "delete",
            (artifact,),
            lambda _: None,
            parameters,
            "governed-runtime",
            state="deleted",
            open_values=False,
        )

    def restore(self, previous, artifact, *, parameters=None):
        if self.metadata(previous)["state"] != "deleted":
            raise ValueError("restoration requires a deleted predecessor")
        if self.metadata(artifact)["state"] != "active":
            raise ValueError("restoration requires an active replacement")
        return self._execute(
            "restore",
            (previous, artifact),
            lambda values: values[1],
            parameters,
            "governed-runtime",
            metadata_only=(previous,),
        )

    def ancestors(self, artifact):
        with self._lock:
            pending, visited = [artifact], set()
            identities = set()
            while pending:
                current = pending.pop()
                if current in visited:
                    continue
                visited.add(current)
                manifest = self.metadata(current)
                identities.add(current.reference.object_id)
                identities.update(item["object_id"] for item in manifest["external_inputs"])
                pending.extend(GovernedArtifact.from_dict(item) for item in manifest["parents"])
            return frozenset(identities)

    def import_publication(
        self,
        publication,
        *,
        group,
        field,
        operation="import",
        parameters=None,
        claims=(),
        publications=(),
        decide=None,
        validate=None,
    ):
        """Admit an external native field without exposing it through public reveal.

        Carried objects retain the source's native ancestry and signed claim
        records. The endpoint supplies its own operation and metadata decisions.
        """
        if publication.object_type == ARTIFACT_TYPE:
            raise ValueError("use receive with an artifact bundle to retain its existing evidence")
        if not isinstance(operation, str) or not operation.strip():
            raise ValueError("operation requires a nonempty name")
        if validate is not None and not callable(validate):
            raise TypeError("external content validation requires a callback")
        with self._lock:
            for wire in publications:
                self.store.put(tn.GovernedObject.parse(wire))
            self.store.put(publication)
            reference = ValueReference(publication.id, field, group)
            use = tn.UseContext(self.application, self.purpose, operation)

            def accept(ctx):
                return self.accept_metadata(ctx) is True and (decide is None or decide(ctx) is True)

            view = self.session.governance(publication)
            # A carried group is admitted on the governance of the object that holds it.
            held = view if group in publication.group_names else self.session.governance(
                holder(publication, group))
            held.accept(use=use, groups=[group], decide=accept)
            lineage = {}
            if claims:
                pending = [publication.id]
                while pending:
                    identity = pending.pop()
                    if identity in lineage:
                        continue
                    if len(lineage) >= 10000:
                        raise EvidenceError("external ancestry exceeds the configured object limit")
                    ancestor = self.store.read(identity)
                    lineage[identity] = ancestor
                    pending.extend(
                        source.object_id
                        for source in self.session.governance(ancestor).governance.sources
                    )
            verified_claims = []
            for identity in claims:
                record = self._record(identity)
                if record.body["kind"] != "Claim" or not isinstance(
                    record.body["details"].get("statement"), str
                ):
                    raise EvidenceError("external claim reference is not a claim")
                subjects = tuple(ValueReference(**item) for item in unpack_references(record.body["inputs"]))
                if not subjects or any(
                    subject.object_id not in lineage
                    or subject.field
                    not in lineage[subject.object_id]
                    .envelope.get(subject.group, {})
                    .get("field_hashes", {})
                    for subject in subjects
                ):
                    raise EvidenceError("external claim subject is not a contributing signed field")
                verified_claims.append(
                    Claim(record.id, record.writer, subjects, record.body["details"]["statement"])
                )
            parameters = _json(parameters or {})
            if not isinstance(parameters, dict):
                raise TypeError("operation parameters require a JSON object")
            request = Request(
                self.application,
                self.purpose,
                operation,
                (reference,),
                (publication.writer,),
                tuple(view.governance.policies),
                tuple(verified_claims),
                "governed-runtime",
                (parameters,),
            )
            call_id = uuid4().hex
            decision = self._authorize(request, call_id)
            try:
                data = receive_routed(self.session, publication, use=use, groups=[group],
                                      decide=lambda source, groups: accept)
                if validate is not None and validate(data) is not True:
                    raise EvidenceError("external content validation refused the publication")
                value = data.get(field, group=group)
                return self._publish(
                    value, (), (), (data,), request, decision, call_id, external_inputs=(reference,)
                )
            except Exception as exc:
                self._append(
                    "Failure",
                    request,
                    call_id,
                    {"decision_id": decision, "error_type": type(exc).__name__},
                )
                raise

    def reveal(self, artifact, *, destination):
        if not isinstance(destination, str) or not destination.strip():
            raise ValueError("disclosure requires a named destination")
        with self._lock:
            request, _ = self._request("reveal", (artifact,), {}, destination)
            call_id = uuid4().hex
            decision = self._authorize(request, call_id)
            try:
                _, value = self._open(artifact, request)
                self._append(
                    "Disclosure",
                    request,
                    call_id,
                    {"decision_id": decision, "delivery": "prepared-for-return"},
                )
                return value
            except Exception as exc:
                self._append(
                    "Failure",
                    request,
                    call_id,
                    {"decision_id": decision, "error_type": type(exc).__name__},
                )
                raise

    def _include(self, carrier):
        if isinstance(self.store, NativeObjects):
            self.store.include(carrier)
        else:
            for obj in carrier.objects():
                self.store.put(obj)

    def _closure(self, artifact, *, max_objects=10000, stop_ids=(), include_tape=False):
        pending = [artifact.reference.object_id, artifact.decision_id, artifact.result_id]
        stopped = set(stop_ids)
        visited = {}
        while pending:
            identity = pending.pop()
            if identity in visited or identity in stopped:
                continue
            if len(visited) >= max_objects:
                raise EvidenceError("artifact closure exceeds the configured object limit")
            obj = self.store.read(identity)
            visited[identity] = obj
            view = self.session.governance(obj)
            pending.extend(source.object_id for source in view.governance.sources)
            if obj.object_type == ARTIFACT_TYPE and "evidence" in obj.envelope:
                data = self.session.receive(
                    obj,
                    use=tn.UseContext(self.application, self.purpose, "inspect"),
                    groups=["evidence"],
                    decide=self._admit,
                )
                manifest = data.get("manifest", group="evidence")
                if manifest:
                    pending.extend(
                        [
                            manifest["decision_id"],
                            *manifest["claims"],
                            *manifest["action_records"],
                        ]
                    )
                    pending.extend(item["object_id"] for item in manifest["external_inputs"])
                    for parent in manifest["parents"]:
                        handle = GovernedArtifact.from_dict(parent)
                        pending.extend(
                            [handle.reference.object_id, handle.decision_id, handle.result_id]
                        )
            elif obj.object_type == "experiment.evidence":
                record = self._record(identity)
                if include_tape and record.body["previous"]:
                    pending.append(record.body["previous"])
                if record.body["kind"] == "Decision":
                    pending.extend(record.body["details"].get("action_progress", ()))
                pending.extend(item["object_id"] for item in unpack_references(record.body["inputs"]))
        return visited

    def _carried(
        self, artifact, *, parents=(), max_objects=10000, manifest=None,
        parent_metadata=None, metadata_cache=None, carrier_cache=None,
    ):
        metadata_cache = {} if metadata_cache is None else metadata_cache
        carrier_cache = {} if carrier_cache is None else carrier_cache
        if artifact in carrier_cache:
            return carrier_cache[artifact]
        if manifest is None:
            manifest = self._metadata(artifact, metadata_cache)[1]
        if not parents:
            parents = tuple(GovernedArtifact.from_dict(item) for item in manifest["parents"])
        if parent_metadata is None:
            parent_metadata = tuple(self._metadata(parent, metadata_cache) for parent in parents)
        retained_parents, inherited = [], set()
        for parent, (_, parent_manifest, _) in zip(parents, parent_metadata, strict=True):
            if parent.carrier is None:
                parent = self._carried(
                    parent, max_objects=max_objects, manifest=parent_manifest,
                    metadata_cache=metadata_cache, carrier_cache=carrier_cache,
                )
            retained_parents.append(parent.carrier)
            inherited.update((parent.reference.object_id, parent.decision_id, parent.result_id))
            inherited.update(parent_manifest["claims"])
            inherited.update(parent_manifest["action_records"])
        native = self._closure(artifact, max_objects=max_objects, stop_ids=inherited)
        support = tuple(obj for identity, obj in native.items()
                        if identity != artifact.reference.object_id)
        carriers = tuple(retained_parents)
        carrier = CarriedPublication(native[artifact.reference.object_id], carriers, support)
        carried = replace(artifact, carrier=carrier)
        carrier_cache[artifact] = carried
        return carried

    def export(self, artifact, *, max_objects=10000):
        with self._lock:
            self._metadata(artifact)
            native = self._closure(artifact, max_objects=max_objects)
            handle = GovernedArtifact.from_dict(artifact.to_dict())
            return ArtifactBundle(handle, tuple(obj.forward() for obj in native.values()))

    def receive(self, bundle, *, max_objects=10000, max_bytes=64 * 1024 * 1024):
        if not isinstance(bundle, ArtifactBundle):
            raise TypeError("endpoint transfer requires an ArtifactBundle")
        return self.receive_many(
            (bundle.artifact,), publications=bundle.publications,
            max_objects=max_objects, max_bytes=max_bytes,
        )[0]

    def receive_many(
        self, artifacts, *, publications, max_objects=10000, max_bytes=64 * 1024 * 1024,
    ):
        """Admit one bounded native transfer before retaining any of its artifacts."""
        artifacts, publications = tuple(artifacts), tuple(publications)
        if any(not isinstance(artifact, GovernedArtifact) for artifact in artifacts):
            raise TypeError("artifact transfer requires GovernedArtifact handles")
        if (len(artifacts) > max_objects or len(publications) > max_objects
                or sum(map(len, publications)) > max_bytes):
            raise EvidenceError("artifact transfer exceeds configured limits")
        with self._lock:
            received = NativeObjects()
            for wire in publications:
                received.put(tn.GovernedObject.parse(wire))
            handles = tuple(
                GovernedArtifact.from_dict(artifact.to_dict()) for artifact in artifacts
            )
            retained = self.store
            try:
                self.store = received
                metadata_cache, carrier_cache = {}, {}
                for artifact in handles:
                    self._metadata(artifact, metadata_cache)
                carried = tuple(
                    self._carried(
                        artifact, max_objects=max_objects, metadata_cache=metadata_cache,
                        carrier_cache=carrier_cache,
                    )
                    for artifact in handles
                )
            finally:
                self.store = retained
            for artifact in carried:
                self._include(artifact.carrier)
            return carried
