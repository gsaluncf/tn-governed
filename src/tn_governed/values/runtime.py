"""String operations over native TN publications.

The application process is trusted to enforce authorization. Callers with control
over the process or independent reader keys can access plaintext outside this API.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, replace
from uuid import uuid4

import tn
from tn_governed.native_objects import CarriedPublication, NativeObjects

from .evidence import OBJECT_ID, EvidenceError, EvidenceRecorder, check_monitor
from .obligations import ObligationResult as ObligationResult
from .obligations import ObligationRun, run_obligations
from .references import unpack_references
from .string import (
    OperationDenied, StringMetadataProvider, TNString, ValueReference, _active, _exposure,
)
from .holders import holds_field

STRING_TYPE = "experiment.string"
STRING_SCHEMA = "tn.string-bindings.v1"
STRING_POLICY_SCHEMA = "tn.string-policy.v1"


@dataclass(frozen=True)
class Claim:
    id: str
    issuer: str
    subjects: tuple[ValueReference, ...]
    statement: str


@dataclass(frozen=True)
class Request:
    application: str
    purpose: str
    operation: str
    inputs: tuple[ValueReference, ...]
    writers: tuple[str, ...]
    policies: tuple
    claims: tuple[Claim, ...]
    destination: str | None = None
    parameters: tuple = ()


@dataclass(frozen=True)
class Assessment:
    permit: bool
    reason: str
    obligations: tuple[str, ...] = ()
    claim_judgments: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Rules:
    """Explicit local demonstration evaluator, not an interpreter of arbitrary prose.

    It accepts configured native contracts. Extra claims are considered informative;
    another receiver may supply a different evaluator and reach a different decision.
    """

    writers: frozenset[str]
    policies: tuple
    operations: frozenset[str]
    destinations: frozenset[str]

    def accepts_metadata(self, ctx):
        return (ctx.writer in self.writers and ctx.object_type == STRING_TYPE
                and bool(ctx.policies)
                and all(any(p.matches_contract(expected) for expected in self.policies)
                        for p in ctx.policies))

    def __call__(self, request):
        judgments = tuple((claim.id, "informative") for claim in request.claims)
        trusted = all(writer in self.writers for writer in request.writers)
        contracts = bool(request.policies) and all(
            any(policy.matches_contract(expected) for expected in self.policies)
            for policy in request.policies
        )
        allowed = trusted and contracts and request.operation in self.operations
        if request.operation == "reveal":
            allowed = allowed and request.destination in self.destinations
        return Assessment(bool(allowed), "configured receiver rules", claim_judgments=judgments)


def publish_source(session, store=None, fields=None, *, policy=None, string_metadata=None):
    """Local origination helper. A real driver must authorize retrieval before this step."""
    if fields is None and isinstance(store, dict):
        fields, store = store, None
    store = NativeObjects() if store is None else store
    if not fields or any(not isinstance(k, str) or not k or type(v) is not str
                         for k, v in fields.items()):
        raise TypeError("source requires nonempty string fields")
    policy = policy or session.policy(STRING_TYPE)
    data = session.create({}, policy, object_type=STRING_TYPE, group="strings")
    data = data.policy_output(STRING_TYPE, {
        "strings": fields, "evidence": {"manifest": {"schema": STRING_POLICY_SCHEMA,
            "bindings": {name: {"claims": [], "actions": []} for name in fields}}},
    })
    data.bind_manifest("evidence")
    publication = session.release(
        data, use=tn.UseContext("local-source", "string-experiment", "originate"),
        to="governed-runtime", object_type=STRING_TYPE,
        decide=lambda ctx: len(ctx.policies) == 1 and ctx.policies[0].matches_contract(policy),
    )
    store.put(publication)
    carried = CarriedPublication(publication)
    return {name: TNString(ValueReference(publication.id, name), metadata_provider=string_metadata,
                           publication=carried)
            for name in fields}


class Context:
    """Trusted string application around an explicitly supplied native TN Session."""

    def __init__(self, session, recorder: EvidenceRecorder, evaluator: Callable, *,
                 application, purpose, metadata_accept=None, obligations=None,
                 string_metadata: StringMetadataProvider | None = None):
        if recorder.session is not session:
            raise ValueError("recorder must belong to this endpoint session")
        tn.UseContext(application, purpose, "inspect")  # Native nonempty validation.
        self.session = session
        self.recorder = recorder
        self.evaluator = evaluator
        self.application = application
        self.purpose = purpose
        self.string_metadata = string_metadata
        self.metadata_accept = metadata_accept or getattr(evaluator, "accepts_metadata", None)
        if self.metadata_accept is None:
            raise TypeError("explicit metadata admission callback required")
        self.obligations = dict(obligations or {})
        self._tokens = []

    def __enter__(self):
        self._tokens.append(_active.set(self))
        return self

    def __exit__(self, *_):
        _active.reset(self._tokens.pop())

    @contextmanager
    def exposure(self, destination):
        if not isinstance(destination, str) or not destination:
            raise ValueError("exposure requires a named destination")
        token = _exposure.set((self.recorder.context_id, destination))
        try:
            yield self
        finally:
            _exposure.reset(token)

    def store_object(self, identity):
        return self.recorder.store.read(identity)

    def _adopt(self, values):
        """Use the native objects owned by supplied values in this endpoint."""
        adopted = {}
        store = self.recorder.store
        native = isinstance(store, NativeObjects)
        for value in values:
            carried = getattr(value, "publication", None)
            if carried is None:
                continue
            key = id(carried)
            previous = adopted.get(key)
            identity = previous[1] if previous is not None else carried.identity
            if identity != value.reference.object_id:
                raise EvidenceError("carried publication differs from the value reference")
            if previous is not None:
                continue
            if native:
                store.include(carried)
            else:
                for publication in carried.objects():
                    try:
                        store.read(publication.id)
                    except FileNotFoundError:
                        store.put(publication)
            adopted[key] = (carried, identity)

    def _retain_publication(self, data, publication):
        self.recorder.store.put(publication)
        if isinstance(self.recorder.store, NativeObjects):
            history = data.history
            for ancestor in history:
                self.recorder.store.put(ancestor)
            self.recorder.store.link(publication.id, tuple(
                obj.id for obj in history if obj.id != publication.id))

    def _policy_credentials(self, publication):
        if getattr(self, "resolver", None) is None:
            return []
        governance = self.session.governance(publication).governance
        pending = [policy.revision_id for policy in governance.policies if policy.revision_id]
        revisions = set()
        while pending:
            identity = pending.pop()
            if identity in revisions:
                continue
            revision = self.policy_dag.get(identity)
            if revision is None:
                raise EvidenceError("carried policy revision is not admitted")
            revisions.add(identity)
            pending.extend(parent.revision_id for parent in revision.parents)
        records = [binding.edition_record_id for binding in governance.dataset_bindings]
        # A newly issued original is registered after signing. Its edition identifies
        # the final signed object, so that credential travels beside the source.
        direct = self.editions.get(publication.id)
        if direct is not None:
            records.append(direct.id)
        return [*sorted(revisions), *records]

    def _action_support(self, actions, records):
        """Check required actions and return the native receipts needed to inspect them.

        With the shared-facts prototype on, an identical action list is checked once per
        operation: ``records`` lives for one operation, so the result never outlives it.
        """
        shared = getattr(self, "share_manifest_facts", False)
        key = ("action-support", tuple(actions))
        if shared and key in records:
            return list(records[key])
        support = self._check_action_support(actions, records)
        if shared:
            records[key] = tuple(support)
        return support

    def _check_action_support(self, actions, records):
        support = []
        for identity in actions:
            decision = self._record(identity, records)
            body = decision.body
            details = body["details"]
            obligations = details.get("obligations")
            discharged = details.get("discharged")
            if (body["kind"] != "Decision" or details.get("permitted") is not True
                    or not isinstance(obligations, list) or not obligations
                    or not isinstance(discharged, list) or len(discharged) != len(obligations)):
                raise EvidenceError("invalid signed required-action decision")
            support.append(identity)
            for name, step in zip(obligations, discharged, strict=True):
                if (not isinstance(step, dict) or step.get("obligation") != name
                        or step.get("satisfied") is not True
                        or not isinstance(step.get("evidence"), str) or not step["evidence"].strip()):
                    raise EvidenceError("required action lacks completion evidence")
                receipt = step["evidence"]
                if OBJECT_ID.fullmatch(receipt):
                    received = self._record(receipt, records)
                    if name == "monitor":
                        check_monitor(decision, received)
                    support.append(receipt)
                elif name == "monitor":
                    raise EvidenceError("monitoring requires a signed receipt")
        return support

    def _record(self, identity, records):
        if identity not in records:
            records[identity] = self.recorder.read(identity)
        return records[identity]

    def _policy_carrier(self, publication, binding):
        """Carry original claims, action receipts and policy credentials by their signed IDs."""
        support = [*binding["claims"], *self._action_support(binding["actions"], {})]
        support.extend(self._policy_credentials(publication))
        return CarriedPublication(publication, support=tuple(
            self.store_object(identity) for identity in dict.fromkeys(support)))

    def _received_carrier(self, value, binding, *, shared):
        """Retain only the native ancestry and evidence needed by a verified received handle."""
        from .evidence import EVIDENCE_TYPE, referenced_publications

        active, count = set(), [0]

        def collect(identity, depth=0):
            if depth > 256:
                raise EvidenceError("received evidence exceeds the native depth limit")
            if identity in active:
                raise EvidenceError("received evidence contains a dependency cycle")
            if identity in shared:
                return shared[identity]
            count[0] += 1
            if count[0] > 65536:
                raise EvidenceError("received evidence exceeds the native object limit")
            active.add(identity)
            try:
                obj = self.store_object(identity)
                governance = self.session.governance(obj).governance
                dependencies = {source.object_id for source in governance.sources}
                dependencies.update(policy.revision_id for policy in governance.policies
                                    if policy.revision_id is not None)
                dependencies.update(item.edition_record_id for item in governance.dataset_bindings)
                if obj.object_type == EVIDENCE_TYPE:
                    record = self.recorder.read(identity)
                    dependencies.update(item.id for item in referenced_publications(
                        (record.body["inputs"], record.body["details"]), self.store_object))
                revision = getattr(self, "policy_dag", None)
                revision = None if revision is None else revision.get(identity)
                if revision is not None:
                    dependencies.update(parent.revision_id for parent in revision.parents)
                dependencies.discard(identity)
                parents = tuple(collect(parent, depth + 1) for parent in sorted(dependencies))
                shared[identity] = CarriedPublication(obj, parents=parents)
                return shared[identity]
            finally:
                active.remove(identity)

        if "actions" in binding and "parents" not in binding:
            return self._policy_carrier(self.store_object(value.reference.object_id), binding)
        root = collect(value.reference.object_id)
        references = (value.decision_id, value.result_id, *binding.get("claims", ()))
        parents = (root, *(collect(identity) for identity in references if identity is not None))
        return CarriedPublication(root.object, parents=parents)

    def _metadata(self, value):
        self._adopt((value,))
        obj = self.store_object(value.reference.object_id)
        use = tn.UseContext(self.application, self.purpose, "inspect-claims")

        data = self.session.receive(
            obj, use=use,
            groups=["evidence"], decide=self.metadata_accept,
        )
        manifest = data.get("manifest", group="evidence")
        if not isinstance(manifest, dict) or manifest.get("schema") not in {STRING_SCHEMA, STRING_POLICY_SCHEMA}:
            raise EvidenceError("missing signed string manifest")
        if manifest["schema"] == STRING_POLICY_SCHEMA:
            binding = manifest.get("bindings", {}).get(value.reference.field)
            if (not isinstance(binding, dict) or set(binding) != {"claims", "actions"}
                    or not isinstance(binding["actions"], list) or not isinstance(binding["claims"], list)
                    or not holds_field(obj, "strings", value.reference.field)
                    or value.reference.group != "strings"
                    or value.decision_id is not None or value.result_id is not None):
                raise EvidenceError("invalid signed string binding")
            self._action_support(binding["actions"], {})
        else:
            def ancestor(identity):
                parent = self.store_object(identity)
                view = self.session.governance(parent)
                group = "evidence" if "evidence" in parent.group_names else value.reference.group
                view.accept(use=use, groups=[group], decide=self.metadata_accept)
                return view

            tn.LineageVerifier(max_objects=65536, max_depth=256).verify(
                self.session.governance(obj), tn.DatasetCatalog(), tn.PolicyDag(), ancestor,
            )
            binding = manifest.get("bindings", {}).get(value.reference.field)
            if not isinstance(binding, dict) or set(binding) != {"claims", "parents", "decision_id"}:
                raise EvidenceError("missing signed field binding")
            if not isinstance(binding["claims"], list) or not isinstance(binding["parents"], (list, dict)):
                raise EvidenceError("invalid signed string lineage")
            decision_id = binding["decision_id"]
            if decision_id is not None:
                if decision_id != value.decision_id or value.result_id is None:
                    raise EvidenceError("derived string requires its signed decision/result citations")
                result = self.recorder.read(value.result_id)
                decision = self.recorder.read(decision_id)
                rb, db = result.body, decision.body
                if (rb["kind"] != "Result" or db["kind"] != "Decision"
                        or result.writer != obj.writer or decision.writer != obj.writer
                        or rb["details"].get("output") != value.reference.to_dict()
                        or rb["details"].get("decision_id") != decision_id
                        or rb["inputs"] != binding["parents"]
                        or rb["details"].get("claims") != binding["claims"]
                        or db["details"].get("permitted") is not True
                        or any(rb[key] != db[key] for key in (
                            "context_id", "call_id", "operation", "inputs", "application", "purpose",
                        ))):
                    raise EvidenceError("result citation does not bind this string to its decision")
            elif value.decision_id is not None or value.result_id is not None:
                raise EvidenceError("origin has unexpected derived citations")
        claims = []
        for identity in binding["claims"]:
            record = self.recorder.read(identity)
            if record.body["kind"] != "Claim":
                raise EvidenceError("claim reference does not identify a claim")
            statement = record.body["details"].get("statement")
            if not isinstance(statement, str) or not statement.strip():
                raise EvidenceError("invalid signed claim statement")
            claims.append(Claim(record.id, record.writer,
                                tuple(ValueReference(**r) for r in unpack_references(record.body["inputs"])),
                                statement))
        return data, binding, tuple(claims)

    def inspect(self, value):
        data, _, claims = self._metadata(value)
        return Request(self.application, self.purpose, "inspect", (value.reference,),
                       (data.snapshot.writer,), tuple(data.policies), claims)

    def _append(self, kind, request, call_id, details):
        if kind != "Claim" and request.operation not in {"select", "reveal", "model_handoff", "compare", "truth", "is_integer"}:
            request = replace(request, inputs=())
        return self.recorder.append(
            kind, call_id=call_id, application=self.application, purpose=self.purpose,
            operation=request.operation, inputs=request.inputs,
            destination=request.destination, details=details,
        )

    def _prepare(self, operation, values, destination, parameters, call_id):
        base = Request(self.application, self.purpose, operation,
                       tuple(v.reference for v in values), (), (), (), destination, parameters)
        actions = ObligationRun()
        cause = None
        try:
            metadata = [self._metadata(value) for value in values]
            claims = {claim.id: claim for _, _, cs in metadata for claim in cs}
            request = replace(base,
                writers=tuple(data.snapshot.writer for data, _, _ in metadata),
                policies=tuple(policy for data, _, _ in metadata for policy in data.policies),
                claims=tuple(claims.values()))
            assessment = self.evaluator(request)
            if (not isinstance(assessment, Assessment) or type(assessment.permit) is not bool
                    or not isinstance(assessment.reason, str)
                    or not isinstance(assessment.obligations, tuple)
                    or any(not isinstance(name, str) or not name for name in assessment.obligations)):
                raise ValueError("evaluator did not return a valid explicit assessment")
            if operation == "reveal" and (not isinstance(destination, str) or not destination):
                assessment = Assessment(False, "exposure requires a named destination")
            permitted = assessment.permit
            if permitted:
                actions = run_obligations(request, assessment.obligations, self.obligations)
                permitted = actions.complete
                cause = actions.error
            details = {
                "permitted": permitted, "requested_permit": assessment.permit,
                "reason": "decision could not be completed" if cause else assessment.reason,
                "obligations": list(assessment.obligations),
                **actions.record_details(),
                "policies": [{"authority": p.governed_by, "policy": p.policy_ref,
                              "revision": p.revision_id} for p in request.policies],
                "considered_claims": [claim.id for claim in request.claims],
                "claim_judgments": [list(j) for j in assessment.claim_judgments],
            }
        except Exception as exc:
            # A failed decision is not an authorization; avoid logging arbitrary exception text.
            request, metadata, permitted = base, [], False
            cause = exc
            details = {"permitted": False, "reason": "decision could not be completed",
                       **actions.record_details(), "error_type": type(exc).__name__}
        if permitted and not actions.steps and operation != "reveal":
            return request, metadata, None
        decision_id = self._append("Decision", request, call_id, details)
        if not permitted:
            self._append("Refusal", request, call_id, {"decision_id": decision_id,
                                                       "reason": details["reason"]})
            raise OperationDenied(f"{operation} was not permitted; decision {decision_id}") from cause
        return request, metadata, decision_id

    def _open_values(self, request, values):
        """Native admission and business decrypt; called only after a recorded permit."""
        working = []
        for value in values:
            obj = self.store_object(value.reference.object_id)
            use = tn.UseContext(self.application, self.purpose, request.operation)
            # Native receipt asks this object and each holder of a carried group.
            data = self.session.receive(
                obj, use=use, groups=["strings", "evidence"],
                decide=lambda ctx, use=use: ctx.use_context == use and self.metadata_accept(ctx),
            )
            content = data.get(value.reference.field, group="strings")
            if type(content) is not str:
                raise TypeError("selected value is not a string")
            working.append((data, content))
        return working

    def compare(self, left: TNString, right: str, *, operation: str) -> bool:
        """Reject comparisons that require opening protected string content.

        Metadata comparisons are handled separately. This method requires an
        active context and raises NotImplementedError before opening content.
        """
        if _active.get() is not self:
            raise OperationDenied("protected comparison requires this active context")
        raise NotImplementedError("protected comparison execution is not implemented yet")

    def perform(self, operation, values, *, destination=None, parameters=()):
        if operation not in {
            "copy", "upper", "lower", "slice", "index", "repeat", "concat", "attest", "reveal",
        }:
            raise ValueError("unsupported string operation")
        literal_concat = operation == "concat" and bool(parameters)
        if literal_concat and (
            len(parameters) != 2 or type(parameters[0]) is not str
            or parameters[1] not in {"left", "right"}
        ):
            raise TypeError("literal concat requires text and its operand position")
        if len(values) != (2 if operation == "concat" and not literal_concat else 1):
            raise ValueError("wrong number of governed inputs")
        call_id = uuid4().hex
        request, metadata, decision_id = self._prepare(
            operation, values, destination, parameters, call_id,
        )
        try:
            claims = list(dict.fromkeys(claim.id for claim in request.claims))
            if operation in {"copy", "attest"}:
                if operation == "attest":
                    claim_id = self._append("Claim", request, call_id, {"statement": parameters[0]})
                    claims.append(claim_id)
                if operation == "copy" and decision_id is None:
                    return values[0]
                # An endorsement can forward the original signed, encrypted text.
                # Retaining ciphertext does not require opening the business group.
                data = metadata[0][0].copy()  # Keep unopened strings as native retained ciphertext.
                field = values[0].reference.field
            else:
                opened = self._open_values(request, values)
                data, content = opened[0]
                if operation == "reveal":
                    # Persist before returning control/plaintext to the caller.
                    self._append("Disclosure", request, call_id, {
                        "decision_id": decision_id, "subject": values[0].reference.to_dict(),
                        "delivery": "prepared-for-return",  # Not proof a downstream sink received it.
                    })
                    return content
                if operation == "upper":
                    content = content.upper()
                elif operation == "lower":
                    content = content.lower()
                elif operation == "slice":
                    content = content[slice(*parameters)]
                elif operation == "index":
                    content = content[parameters[0]]
                elif operation == "repeat":
                    content = content * parameters[0]
                elif operation == "concat":
                    if literal_concat:
                        literal, side = parameters
                        content = literal + content if side == "left" else content + literal
                    else:
                        content += opened[1][1]
                field = "value"
                data = data.policy_output(STRING_TYPE, {"strings": {field: content}},
                                          inputs=[item[0] for item in opened[1:]])
            actions = [action for _, binding, _ in metadata for action in binding.get("actions", ())]
            if decision_id is not None:
                actions.append(decision_id)
            binding = {"claims": claims, "actions": list(dict.fromkeys(actions))}
            data.set(None, {"manifest": {"schema": STRING_POLICY_SCHEMA, "bindings": {field: binding}}},
                     group="evidence")
            data.bind_manifest("evidence")
            use = tn.UseContext(self.application, self.purpose, "publish")
            publication = self.session.release(
                data, use=use, to="governed-runtime", object_type=STRING_TYPE,
                decide=lambda ctx: ctx.writer == self.session.did and ctx.use_context == use
                and all(any(p.matches_contract(q) for q in request.policies) for p in ctx.policies)
                and all(any(p.matches_contract(q) for q in ctx.policies) for p in request.policies),
            )
            self.recorder.store.put(publication)
            return TNString(ValueReference(publication.id, field), metadata_provider=self.string_metadata,
                            publication=self._policy_carrier(publication, binding))
        except Exception as exc:
            # Execution/key/storage failures are not represented as successful results.
            self._append("Failure", request, call_id,
                         {"decision_id": decision_id, "error_type": type(exc).__name__})
            raise
