"""Locally authorized operations over portable native TN artifacts."""

from __future__ import annotations

import threading
from uuid import uuid4

import tn

from . import artifact_transfer
from .artifact_publication import publish_artifact
from .artifact_types import ARTIFACT_TYPE, MANIFEST_GROUP, ArtifactBundle, artifact_json
from .artifact_verification import external_claims, imported_field_evidence, verify_artifact
from .native_objects import NativeObjects
from .values.evidence import EvidenceError, EvidenceRecorder, read_record
from .values.obligations import ObligationRun, run_obligations
from .values.runtime import Assessment, Request
from .values.string import OperationDenied, ValueReference


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
        self.inspect_use = tn.UseContext(application, purpose, "inspect")
        self.evaluator, self.accept_metadata = evaluator, accept_metadata
        self.evidence_policies = tuple(evidence_policies) + (evidence_policy,)
        self.recorder = EvidenceRecorder(session, self.store, evidence_policy)
        self.obligations = dict(obligations or {})
        self._lock = threading.RLock()

    def _record(self, identity):
        return read_record(self.store.read(identity), session=self.session, policy=self.evidence_policies)

    def records(self):
        with self._lock:
            return tuple(self._record(identity) for identity in self.recorder.ids())

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

    def _fail(self, request, call_id, decision, error):
        self._append("Failure", request, call_id, {"decision_id": decision, "error_type": type(error).__name__})

    def _admit(self, context):
        return (
            context.object_type == ARTIFACT_TYPE
            and context.object.manifest_group == MANIFEST_GROUP
            and bool(context.policies)
            and self.accept_metadata(context) is True
        )

    def metadata(self, artifact):
        with self._lock:
            return verify_artifact(self, artifact)[1]

    def claims(self, artifact):
        with self._lock:
            return verify_artifact(self, artifact)[2]

    def _request(self, operation, inputs, parameters, destination, policies=(), metadata_only=()):
        _require_names(operation, destination)
        if not isinstance(parameters, dict):
            raise TypeError("operation parameters require a JSON object")
        cache = {}
        metadata = tuple(verify_artifact(self, value, cache) for value in inputs)
        if any(
            item[1]["state"] != "active" and value not in metadata_only
            for value, item in zip(inputs, metadata, strict=True)
        ):
            raise OperationDenied("a deleted version cannot be used as an active input")
        contracts = _contracts((*policies, *(policy for data, _, _ in metadata for policy in data.policies)))
        claims = {claim.id: claim for _, _, claims in metadata for claim in claims}
        request = Request(
            self.application,
            self.purpose,
            operation,
            tuple(value.reference for value in inputs),
            tuple(data.snapshot.writer for data, _, _ in metadata),
            contracts,
            tuple(claims.values()),
            destination,
            (artifact_json(parameters),),
        )
        return request, metadata

    def _authorize(self, request, call_id, *, record=False):
        actions, cause, progress = ObligationRun(), None, []
        details = {"parameters": request.parameters[0], "action_progress": progress}

        def observe(step):
            progress.append(self._append("Observation", request, call_id, {
                "stage": "required-action", "index": len(progress), "obligation": step.name,
                "satisfied": step.satisfied, "evidence": step.evidence,
            }))

        try:
            assessment = self._assess(request)
            permitted = assessment.permit
            if permitted:
                actions = run_obligations(request, assessment.obligations, self.obligations, observe=observe)
                permitted, cause = actions.complete, actions.error
            details.update(_decision_details(request, assessment, permitted, actions))
        except Exception as exc:
            permitted, cause = False, exc
            details.update({**actions.record_details(), "permitted": False,
                            "reason": "decision could not be completed", "error_type": type(exc).__name__})
        if permitted and not assessment.obligations and not record:
            return None
        decision = self._append("Decision", request, call_id, details)
        if not permitted:
            self._append("Refusal", request, call_id, {"decision_id": decision, "reason": details["reason"]})
            raise OperationDenied(f"{request.operation} refused; decision {decision}") from cause
        return decision

    def _assess(self, request):
        assessment = self.evaluator(request)
        if (
            not isinstance(assessment, Assessment)
            or type(assessment.permit) is not bool
            or not isinstance(assessment.reason, str)
        ):
            raise TypeError("evaluator must return an explicit Assessment")
        return assessment

    def _open(self, artifact, request):
        data = self.session.receive(
            self.store.read(artifact.reference.object_id),
            use=tn.UseContext(request.application, request.purpose, request.operation),
            groups=["values", MANIFEST_GROUP],
            decide=self._admit,
        )
        return data, artifact_json(data.get("value", group="values"))

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
        record_use=False,
        open_values=True,
        metadata_only=(),
    ):
        inputs = tuple(inputs)
        with self._lock:
            request, metadata = self._request(
                operation, inputs, artifact_json(parameters or {}), destination, policies, metadata_only
            )
            call_id = uuid4().hex
            decision = self._authorize(request, call_id, record=record_use)
            try:
                pairs = tuple(
                    (metadata[index][0], None) if value in metadata_only else self._open(value, request)
                    for index, value in enumerate(inputs)
                ) if open_values else ()
                value = compute(tuple(value for _, value in pairs))
                opened = tuple(data for data, _ in pairs) if open_values else tuple(item[0] for item in metadata)
                return publish_artifact(self, value, metadata, opened, request, decision, call_id,
                                        claim=claim, dispute=dispute, state=state)
            except Exception as exc:
                self._fail(request, call_id, decision, exc)
                raise

    def originate(self, value, *, policies, operation="originate", parameters=None):
        return self._execute(
            operation, (), lambda _: value, parameters, "governed-runtime", policies=tuple(policies)
        )

    def execute(
        self, operation, inputs, compute, *, parameters=None, destination="governed-runtime", record_use=False
    ):
        if not callable(compute):
            raise TypeError("operation requires an authorized computation callback")
        return self._execute(operation, inputs, compute, parameters, destination, record_use=record_use)

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
            record_use=True,
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
            record_use=True,
            metadata_only=(previous,),
        )

    def import_publication(
        self,
        publication,
        *,
        group,
        field,
        operation="import",
        parameters=None,
        claims=(),
        actions=(),
        publications=(),
        decide=None,
        validate=None,
    ):
        """Admit an external native field without exposing it through public reveal.

        Signed claims retain their original issuers and subjects. The endpoint supplies its own operation and metadata decisions.
        """
        _check_import(publication, operation, validate)
        with self._lock:
            for wire in publications:
                self.store.put(tn.GovernedObject.parse(wire))
            self.store.put(publication)
            reference = ValueReference(publication.id, field, group)

            def accept(ctx):
                return self.accept_metadata(ctx) is True and (decide is None or decide(ctx) is True)

            # Native admission asks the publication and each object on the path to the
            # group's holder. Receipt reuses this route after the endpoint decides.
            use = tn.UseContext(self.application, self.purpose, operation)
            admitted = self.session.admit(publication, use=use, groups=[group], decide=accept)
            bound_claims, bound_actions = (), ()
            metadata_group = publication.manifest_group or MANIFEST_GROUP
            if metadata_group != group and metadata_group in publication.group_names:
                evidence = self.session.receive(publication, use=use, groups=[metadata_group], decide=accept)
                bound_claims, bound_actions = imported_field_evidence(self, evidence, metadata_group, group, field)
            if set(actions) - set(bound_actions):
                raise EvidenceError("action is not attached to the imported field")
            claim_ids = tuple(dict.fromkeys((*bound_claims, *claims)))
            request = self._import_request(publication, reference, admitted.policies, operation, parameters,
                                           external_claims(self, publication, reference, claim_ids, bound_claims))
            call_id = uuid4().hex
            decision = self._authorize(request, call_id)
            try:
                data = self.session.receive(admitted, decide=accept)
                if validate is not None and validate(data) is not True:
                    raise EvidenceError("external content validation refused the publication")
                descriptor = data.get(group=group).get("tn_polars_governance")
                if descriptor and (set(descriptor["claims"]) != set(bound_claims)
                                   or set(descriptor["actions"]) != set(bound_actions)):
                    raise EvidenceError("frame governance differs from the admitted metadata")
                return publish_artifact(self, data.get(field, group=group), (), (data,), request, decision,
                                        call_id, actions=bound_actions)
            except Exception as exc:
                self._fail(request, call_id, decision, exc)
                raise

    def _import_request(self, publication, reference, policies, operation, parameters, claims):
        parameters = artifact_json(parameters or {})
        if not isinstance(parameters, dict):
            raise TypeError("operation parameters require a JSON object")
        return Request(self.application, self.purpose, operation, (reference,), (publication.writer,),
                       tuple(policies), tuple(claims), "governed-runtime", (parameters,))

    def reveal(self, artifact, *, destination):
        if not isinstance(destination, str) or not destination.strip():
            raise ValueError("disclosure requires a named destination")
        with self._lock:
            request, _ = self._request("reveal", (artifact,), {}, destination)
            call_id = uuid4().hex
            decision = self._authorize(request, call_id, record=True)
            try:
                _, value = self._open(artifact, request)
                self._append("Disclosure", request, call_id,
                             {"decision_id": decision, "delivery": "prepared-for-return"})
                return value
            except Exception as exc:
                self._fail(request, call_id, decision, exc)
                raise

    def export(self, artifact, *, max_objects=10000):
        with self._lock:
            return artifact_transfer.export(self, artifact, max_objects=max_objects)

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
        with self._lock:
            return artifact_transfer.receive_many(self, artifacts, publications,
                                                  max_objects=max_objects, max_bytes=max_bytes)


def _require_names(operation, destination):
    if not isinstance(operation, str) or not operation.strip():
        raise ValueError("operation requires a nonempty name")
    if not isinstance(destination, str) or not destination.strip():
        raise ValueError("operation requires a named destination")


def _contracts(policies):
    """One representation per source contract; conflicting representations are refused."""
    contracts = {}
    for policy in policies:
        key = (policy.governed_by, policy.policy_ref, policy.revision_id)
        if key in contracts and not contracts[key].matches_contract(policy):
            raise EvidenceError("conflicting representations of a source contract")
        contracts[key] = policy
    if not contracts:
        raise OperationDenied("a governed artifact requires source governance")
    return tuple(contracts.values())


def _decision_details(request, assessment, permitted, actions):
    details = {
        "permitted": permitted,
        "requested_permit": assessment.permit,
        "reason": assessment.reason,
        "obligations": list(assessment.obligations),
        "claim_judgments": [list(item) for item in assessment.claim_judgments],
        "policies": [
            {"authority": p.governed_by, "policy": p.policy_ref, "revision": p.revision_id}
            for p in request.policies
        ],
        **actions.record_details(),
    }
    if hasattr(assessment, "evaluation"):
        details["evaluation"] = artifact_json(assessment.evaluation)
    return details


def _check_import(publication, operation, validate):
    if publication.object_type == ARTIFACT_TYPE:
        raise ValueError("use receive with an artifact bundle to retain its existing evidence")
    if not isinstance(operation, str) or not operation.strip():
        raise ValueError("operation requires a nonempty name")
    if validate is not None and not callable(validate):
        raise TypeError("external content validation requires a callback")
