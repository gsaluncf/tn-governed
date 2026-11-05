"""Application execution for governed Python primitives over the pinned native TN SDK."""

from dataclasses import replace
import operator
import math
from uuid import uuid4
import weakref

import tn

from tn_governed.native_objects import CarriedPublication

from .evidence import EvidenceError
from .holders import holder, suppliers
from .manifests import BATCH_SCHEMA, POLICY_SCHEMA, SCHEMA, SCHEMAS, result_names, signed_manifest
from .numeric import TNNumeric
from .numeric_codec import KINDS, NUMERIC_TYPES, encode, decode, record_value
from .metadata import DeclaredMetadata, describe
from .obligations import ObligationRun, run_obligations
from .references import unpack_references
from .runtime import Assessment, Claim, Context as StringContext, ObligationResult, Request
from .string import OperationDenied, TNString, ValueReference, _active

VALUE_TYPE = "experiment.primitive"
MAX_SOURCE_PUBLICATION_CELLS = 4096
BINARY = {
    "add": operator.add, "subtract": operator.sub, "multiply": operator.mul,
    "true_divide": operator.truediv, "divmod": divmod,
    "floor_divide": operator.floordiv, "modulo": operator.mod, "power": operator.pow,
    "bit_and": operator.and_, "bit_or": operator.or_, "bit_xor": operator.xor,
    "left_shift": operator.lshift, "right_shift": operator.rshift,
}
OPERATIONS = frozenset({
    "select", "model_handoff", "copy", "attest", "upper", "lower", "strip", "replace", "slice", "index",
    "repeat", "concat", "reveal", "compare", "to_int", "to_string", "negate",
    "positive", "absolute", "invert", "round", "trunc", "floor", "ceil",
    "conjugate", "real", "imag", "numerator", "denominator", "as_integer_ratio",
    "is_integer", "truth", "power_mod", "quantize", "sqrt", "normalize", "exp", "ln", "log10", *BINARY,
})


class _CheckedMetadata(list):
    """Signed manifests and ordered fields retained for one prepared operation."""

    def __init__(self, context, values):
        super().__init__()
        self.context = context
        self.references = tuple(value.reference for value in values)
        self.manifests = {}


class Context(StringContext):
    def __init__(self, session, recorder, evaluator, *, application, purpose, actor,
                 metadata_accept=None, resolver=None):
        super().__init__(session, recorder, evaluator, application=application, purpose=purpose,
                         metadata_accept=metadata_accept)
        self.actor = actor
        self.resolver = resolver
        self.string_metadata = DeclaredMetadata(self)
        self.obligations["monitor"] = self._monitor
        self.catalog = tn.DatasetCatalog()
        self.policy_dag = resolver.policy_dag if resolver is not None else tn.PolicyDag()
        self.editions = {}
        # Bind the stable metadata/attestation handoff to this enrolled endpoint.
        # Content operations retain explicit per-call use and per-input selection.
        owner = weakref.ref(self)
        def accept_received(ctx):
            context = owner()
            return context is not None and context._admit(ctx)
        writer = session.did
        session.configure_receive(use=tn.UseContext(application, purpose, "inspect-claims"),
                                  groups=["evidence"], object_type=VALUE_TYPE, decide=accept_received)
        session.configure_release(use=tn.UseContext(application, purpose, "attest"),
                                  to="governed-runtime", object_type=VALUE_TYPE,
                                  decide=lambda ctx: ctx.writer == writer)
        self.workflow = session.workflow(receive=purpose, release=purpose)

    def _monitor(self, request):
        identity = self._append("Monitor", request, uuid4().hex, {
            "event": "protected-operation-observed", "actor": self.actor,
        })
        return ObligationResult(True, identity)

    def _append(self, kind, request, call_id, details):
        return super()._append(kind, request, call_id, record_value({**details, "actor": self.actor}))

    def _read(self, value, groups, operation):
        self._adopt((value,))
        obj = self.store_object(value.reference.object_id)
        use = tn.UseContext(self.application, self.purpose, operation)
        if operation == "inspect-claims":
            return self.workflow.receive(obj, selection=self._selections(obj, ["evidence"], use))
        return self.session.receive(obj, use=use, groups=list(groups),
                                    selection=self._selections(obj, groups, use), decide=self._admit)

    def _selections(self, obj, groups, use):
        """The selected edition of each object that supplies one of `groups`."""
        return [self.catalog.select(record.dataset, record.edition, record.id, use)
                for source in suppliers(obj, groups)
                if (record := self.editions.get(source.id)) is not None]

    def _admit(self, ctx):
        if (not self.metadata_accept(ctx) or ctx.use_context.application != self.application
                or ctx.use_context.purpose != self.purpose):
            return False
        if ctx.governance.dataset_bindings:
            if not self.catalog.accepts(ctx, self.policy_dag):
                return False
        return True

    def _verify_legacy_sources(self, obj):
        use = tn.UseContext(self.application, self.purpose, "inspect-claims")
        def ancestor(identity):
            parent = self.store_object(identity)
            view = self.session.governance(parent)
            groups = ["evidence"] if "evidence" in parent.group_names else ["values"]
            view.accept(use=use, groups=groups, decide=self.metadata_accept)
            return view
        tn.LineageVerifier(max_objects=65536, max_depth=256).verify(
            self.session.governance(obj), self.catalog, self.policy_dag, ancestor)

    def hydrate(self, reference, decision_id, result_id, *, kind):
        """Verify a received handle after its edition/authority has been resolved."""
        return self.hydrate_many([(reference, decision_id, result_id, kind)])[0]

    def hydrate_many(self, handles):
        handles = tuple(handles)
        values = []
        kinds = {"str", *KINDS}
        for handle in handles:
            if len(handle) not in (4, 5):
                raise ValueError("received handles require four fields and optional native material")
            reference, decision_id, result_id, kind = handle[:4]
            carried = handle[4] if len(handle) == 5 else None
            if kind not in kinds:
                raise TypeError("unsupported primitive kind")
            cls = TNString if kind == "str" else TNNumeric
            values.append(cls(reference, decision_id, result_id, metadata_provider=self.string_metadata,
                              publication=carried))
        metadata = self._metadata_many(values)
        shared = {}
        for index, ((_, binding, _), handle) in enumerate(zip(metadata, handles, strict=True)):
            if binding["declared"]["kind"] != handle[3]:
                raise EvidenceError("requested type differs from signed primitive kind")
            value = values[index]
            if value.reference.object_id in self.editions and "parents" not in binding:
                key = value.reference.object_id, tuple(binding["claims"]), tuple(binding["actions"])
                if key not in shared:
                    shared[key] = self._policy_carrier(self.store_object(value.reference.object_id), binding)
                carrier = shared[key]
            elif value.publication is None:
                carrier = self._received_carrier(value, binding, shared=shared)
            else:
                continue
            if (not isinstance(carrier, CarriedPublication)
                    or carrier.identity != value.reference.object_id):
                raise ValueError("carried publication differs from the value reference")
            # These wrappers are private to hydration until their checked carriers are attached.
            object.__setattr__(value, "publication", carrier)
        return tuple(values)

    def _signed_result(self, value, writer, records):
        """Check a call's signed Result and Decision once for all cells it produced."""
        key = value.result_id, value.decision_id, writer
        if key not in records:
            result = self._record(value.result_id, records)
            decision = self._record(value.decision_id, records)
            rb, db = result.body, decision.body
            if (rb["kind"] != "Result" or db["kind"] != "Decision"
                    or result.writer != writer or decision.writer != result.writer
                    or rb["details"].get("decision_id") != decision.id
                    or db["details"].get("permitted") is not True
                    or rb["sequence"] <= db["sequence"]
                    or any(rb[name] != db[name] for name in (
                        "context_id", "call_id", "operation", "inputs", "application", "purpose"))):
                raise EvidenceError("primitive is not bound to its authorized result")
            records[key] = rb
        return records[key]

    def _metadata_read(self, value):
        data = self._read(value, ["evidence"], "inspect-claims")
        snapshot = data.snapshot
        envelope = holder(snapshot, value.reference.group).envelope
        manifest = signed_manifest(data)
        if isinstance(manifest, dict) and manifest.get("schema") in {SCHEMA, BATCH_SCHEMA}:
            self._verify_legacy_sources(snapshot)
        return data, manifest, snapshot.writer, envelope

    def _metadata(self, value, *, _reads=None, _records=None):
        reads = {} if _reads is None else _reads
        records = {} if _records is None else _records
        identity = value.reference.object_id
        if identity not in reads:
            reads[identity] = self._metadata_read(value)
        return self._metadata_fields((value,), *reads[identity], records)[0]

    def _metadata_fields(self, values, data, manifest, writer, envelope, records):
        if not isinstance(manifest, dict) or manifest.get("schema") not in SCHEMAS:
            raise EvidenceError("missing signed primitive manifest")
        bindings = manifest.get("bindings", {})
        policy_schema = manifest["schema"] == POLICY_SCHEMA
        result = []
        for value in values:
            binding = bindings.get(value.reference.field)
            if not isinstance(binding, dict):
                raise EvidenceError("missing signed primitive binding")
            expected_kinds = KINDS if isinstance(value, TNNumeric) else {"str"}
            if binding.get("declared", {}).get("kind") not in expected_kinds:
                raise EvidenceError("primitive class differs from signed logical kind")
            if policy_schema:
                if (set(binding) != {"declared", "claims", "actions"} or value.decision_id is not None
                        or value.result_id is not None or value.reference.group != "values"
                        or value.reference.field not in envelope["values"]["field_hashes"]
                        or not isinstance(binding["claims"], list) or not isinstance(binding["actions"], list)):
                    raise EvidenceError("invalid signed policy-bearing value")
                self._action_support(binding["actions"], records)
            else:
                if binding.get("decision_id") != value.decision_id or value.result_id is None:
                    raise EvidenceError("primitive requires its exact signed decision and result")
                rb = self._signed_result(value, writer, records)
                if (not result_names(rb["details"], value.reference, envelope)
                        or rb["inputs"] != binding["parents"]
                        or rb["details"].get("claims") != binding["claims"]):
                    raise EvidenceError("primitive is not bound to its authorized result")
                decision = self._record(value.decision_id, records)
                if decision.body["details"].get("obligations"):
                    binding = {**binding, "actions": [decision.id]}
                    self._action_support(binding["actions"], records)
            claims = []
            for identity in binding["claims"]:
                claim = self._record(identity, records)
                if (claim.body["kind"] != "Claim" or not isinstance(claim.body["details"].get("statement"), str)
                        or not claim.body["details"]["statement"].strip() or not claim.body["inputs"]):
                    raise EvidenceError("invalid signed claim")
                claims.append(Claim(identity, claim.writer,
                                    tuple(ValueReference(**r) for r in unpack_references(claim.body["inputs"])),
                                    claim.body["details"]["statement"]))
            result.append((data, binding, tuple(claims)))
        return result

    def _metadata_many(self, values):
        self._adopt(values)
        groups, records = {}, {}
        for index, value in enumerate(values):
            key = value.reference.object_id, value.reference.group
            groups.setdefault(key, []).append((index, value))
        result = _CheckedMetadata(self, values)
        result.extend([None] * len(values))
        for key, members in groups.items():
            indices, batch = zip(*members, strict=True)
            data, manifest, writer, envelope = self._metadata_read(batch[0])
            checked = self._metadata_fields(batch, data, manifest, writer, envelope, records)
            result.manifests[key] = manifest
            for index, item in zip(indices, checked, strict=True):
                result[index] = item
        return result

    def _decision(self, request, call_id, *, record_permit=True):
        actions = ObligationRun()
        cause = None
        try:
            assessment = self.evaluator(request)
            if (not isinstance(assessment, Assessment) or type(assessment.permit) is not bool
                    or not isinstance(assessment.reason, str)
                    or not isinstance(assessment.obligations, tuple)
                    or any(not isinstance(name, str) or not name for name in assessment.obligations)):
                raise ValueError("an explicit assessment is required")
            permitted = assessment.permit
            if request.operation == "reveal" and not request.destination:
                assessment = Assessment(False, "exposure requires a named destination")
                permitted = False
            if permitted:
                actions = run_obligations(request, assessment.obligations, self.obligations)
                permitted = actions.complete
                cause = actions.error
            details = {"permitted": permitted, "requested_permit": assessment.permit,
                       "reason": "decision could not be completed" if cause else assessment.reason,
                       "obligations": list(assessment.obligations),
                       **actions.record_details(),
                       "policies": [{"authority": p.governed_by, "policy": p.policy_ref,
                                     "revision": p.revision_id} for p in request.policies],
                       "considered_claims": [c.id for c in request.claims],
                       "claim_judgments": [list(j) for j in assessment.claim_judgments]}
        except Exception as exc:
            permitted = False
            cause = exc
            details = {"permitted": False, "reason": "decision could not be completed",
                       **actions.record_details(), "error_type": type(exc).__name__}
        if permitted and not actions.steps and not record_permit:
            return None
        if request.operation in {"select", "reveal", "model_handoff"}:
            details["parameters"] = list(request.parameters)
        identity = self._append("Decision", request, call_id, details)
        if not permitted:
            self._append("Refusal", request, call_id, {"decision_id": identity, "reason": details["reason"]})
            raise OperationDenied(f"{request.operation} refused; decision {identity}") from cause
        return identity

    def _prepare(self, operation, values, destination, parameters, call_id):
        base = Request(self.application, self.purpose, operation,
                       tuple(v.reference for v in values), (), (), (), destination, parameters)
        try:
            items = self._metadata_many(values)
        except Exception as exc:
            decision = self._append("Decision", base, call_id, {
                "permitted": False, "reason": "input admission failed", "error_type": type(exc).__name__})
            self._append("Refusal", base, call_id, {"decision_id": decision, "reason": "input admission failed"})
            raise OperationDenied(f"input admission failed: {type(exc).__name__}") from exc
        claims = {c.id: c for _, _, cs in items for c in cs}
        policies, writers = [], {}
        for value, (data, _, _) in zip(values, items, strict=True):
            identity = value.reference.object_id
            if identity in writers:
                continue
            writers[identity] = data.snapshot.writer
            for policy in data.policies:
                if not any(policy.matches_contract(existing) for existing in policies):
                    policies.append(policy)
        request = replace(base, writers=tuple(writers[value.reference.object_id] for value in values),
                          policies=tuple(policies),
                          claims=tuple(claims.values()))
        return request, items, self._decision(request, call_id, record_permit=operation in {
            "reveal", "model_handoff", "select", "compare", "is_integer", "truth"})

    def _open_values(self, request, values, *, metadata=None):
        if metadata is not None and (
                not isinstance(metadata, _CheckedMetadata) or metadata.context is not self
                or metadata.references != tuple(value.reference for value in values)):
            raise EvidenceError("prepared metadata differs from this context or its ordered inputs")
        result, opened = [], {}
        for value in values:
            key = value.reference.object_id, value.reference.group
            if key not in opened:
                data = self._read(value, [value.reference.group, "evidence"], request.operation)
                manifest = signed_manifest(data) if metadata is None else metadata.manifests[key]
                opened[key] = data, manifest, data.get(None, group=value.reference.group)
            data, manifest, payloads = opened[key]
            payload = payloads[value.reference.field]
            facts = manifest["bindings"][value.reference.field]["declared"]
            content = decode(payload, facts["kind"])
            if describe(content) != facts:
                raise EvidenceError("declared facts do not match the opened content")
            result.append((data, content))
        return result

    def _release_value(self, data, request, *, operation=None):
        use = tn.UseContext(self.application, self.purpose, operation or request.operation)
        def accept_release(ctx):
            return (ctx.writer == self.session.did and ctx.use_context == use
                    and all(any(p.matches_contract(q) for q in request.policies) for p in ctx.policies)
                    and all(any(p.matches_contract(q) for q in ctx.policies) for p in request.policies))
        publication = (self.workflow.release(data, decide=accept_release) if request.operation == "attest"
                       else self.session.release(data, use=use, to="governed-runtime",
                                                 object_type=VALUE_TYPE, decide=accept_release))
        self._retain_publication(data, publication)
        return publication

    def publish_value(self, content, *, request, metadata, claims=None, actions=()):
        """Publish a fresh scalar with every admitted policy, original claim and action receipt."""
        if type(content) not in (str, *NUMERIC_TYPES):
            raise TypeError("unsupported governed result type")
        inputs = {id(data): data for data, _, _ in metadata}
        if not inputs:
            raise ValueError("a calculated value requires admitted governance")
        first, *others = inputs.values()
        data = first.policy_output(VALUE_TYPE, {"values": {"value": encode(content)}}, inputs=others)
        return self._publish_policy(data, "value", describe(content), request, metadata, claims, actions)

    def _publish_policy(self, data, field, declared, request, metadata, claims, actions):
        source_claims = [claim.id for _, _, originals in metadata for claim in originals]
        claims = [*source_claims, *(claims or ())]
        inherited = [action for _, binding, _ in metadata for action in binding.get("actions", ())]
        binding = {"declared": declared, "claims": list(dict.fromkeys(claims)),
                   "actions": list(dict.fromkeys([*inherited, *(a for a in actions if a is not None)]))}
        data.set(None, {"manifest": {"schema": POLICY_SCHEMA, "bindings": {field: binding}}}, group="evidence")
        data.bind_manifest("evidence")
        publication = self._release_value(data, request, operation="publish" if request.operation != "attest" else None)
        cls = TNString if declared["kind"] == "str" else TNNumeric
        return cls(ValueReference(publication.id, field, "values"), None, None,
                   metadata_provider=self.string_metadata, publication=self._policy_carrier(publication, binding))

    def originate_batch(self, cells, policy, *, request, decision_id, call_id):
        """Publish a signed column batch with an address and declared type for each field."""
        cells = tuple(cells)
        if not cells or len(cells) > MAX_SOURCE_PUBLICATION_CELLS:
            raise ValueError(
                f"source publication requires between 1 and {MAX_SOURCE_PUBLICATION_CELLS} cells")
        first_content, first_source = cells[0]
        scope = {key: value for key, value in first_source.items() if key != "row"}
        fields, facts = {}, {}
        for content, source in cells:
            if type(content) not in (str, *NUMERIC_TYPES) or type(content) is not type(first_content):
                raise TypeError("a source batch requires one supported scalar type")
            row = source.get("row")
            if (type(row) is not int or row < 0
                    or {key: value for key, value in source.items() if key != "row"} != scope):
                raise ValueError("source cells must share a column, query, assignment and snapshot")
            field = f"value_{row}"
            if field in fields:
                raise ValueError("duplicate row in source publication")
            fields[field] = encode(content)
            facts[field] = describe(content)
        return self._source_fields(fields, facts, policy, request, decision_id, call_id)

    def originate(self, content, policy, *, source, request, decision_id, call_id):
        return self._source_fields({"value": encode(content)}, {"value": describe(content)},
                                   policy, request, decision_id, call_id)[0]

    def _source_fields(self, fields, facts, policy, request, decision_id, call_id, *, _handles=False):
        """Bind each field to the source rules under this endpoint's signed query admission."""
        if ((request.application, request.purpose, request.operation) != (self.application, self.purpose, "select")
                or not any(policy.matches_contract(p) for p in request.policies)):
            raise ValueError("source policy must be covered by the query request")
        decision = self.recorder.read(decision_id)
        body, details = decision.body, decision.body["details"]
        contract = {"authority": policy.governed_by, "policy": policy.policy_ref, "revision": policy.revision_id}
        claims = list(dict.fromkeys(claim.id for claim in request.claims))
        if (decision.writer != self.session.did or body["kind"] != "Decision"
                or body["context_id"] != self.recorder.context_id or body["call_id"] != call_id
                or (body["application"], body["purpose"], body["operation"])
                != (self.application, self.purpose, "select")
                or details.get("permitted") is not True or contract not in details.get("policies", ())
                or details.get("considered_claims") != claims):
            raise EvidenceError("source fields require this query's signed permit")
        support = {"claims": claims, "actions": [decision_id] if details.get("obligations") else []}
        bindings = {field: {"declared": declared, **support} for field, declared in facts.items()}
        seed = self.session.create({}, policy, object_type=VALUE_TYPE, group="values")
        data = seed.policy_output(VALUE_TYPE, {"values": fields, "evidence": {
            "manifest": {"schema": POLICY_SCHEMA, "bindings": bindings}}})
        data.bind_manifest("evidence")
        publication = self._release_value(data, replace(request, policies=(policy,)))
        carrier = self._policy_carrier(publication, support)
        cls = TNString if next(iter(facts.values()))["kind"] == "str" else TNNumeric
        identity = publication.id
        # SQL hands references directly to its receiver; only that endpoint needs wrappers.
        return (tuple((ValueReference(identity, field, "values"), None, None,
                       facts[field]["kind"], carrier) for field in fields) if _handles else
                tuple(cls(ValueReference(identity, field, "values"), None, None,
                         metadata_provider=self.string_metadata, publication=carrier)
                      for field in fields))

    def compare(self, left, right, *, operation):
        if _active.get() is not self:
            raise OperationDenied("protected comparison requires the active context")
        if isinstance(right, (TNNumeric, TNString)):
            return self.perform("compare", (left, right), parameters=(operation,))
        if type(right) not in (str, bool, *NUMERIC_TYPES):
            raise TypeError("unsupported comparison operand")
        return self.perform("compare", (left,), parameters=(operation, right))

    def perform(self, operation, values, *, destination=None, parameters=()):
        if operation not in OPERATIONS - {"select", "model_handoff"}:
            raise NotImplementedError(f"unsupported governed primitive operation: {operation}")
        if operation not in {"reveal", "attest"} and _active.get() is not self:
            raise OperationDenied("content operations require this active context")
        call_id = uuid4().hex
        request, metadata, decision = self._prepare(operation, values, destination, parameters, call_id)
        try:
            claims = list(dict.fromkeys(c.id for c in request.claims))
            if operation in {"copy", "attest"}:
                if operation == "copy" and decision is None:
                    return values[0]
                data, binding, _ = metadata[0]
                data = data.copy()
                if operation == "attest":
                    claims.append(self._append("Claim", request, call_id, {"statement": parameters[0]}))
                return self._publish_policy(data, values[0].reference.field, binding["declared"],
                                            request, metadata, claims, (decision,))
            else:
                opened = self._open_values(request, values)
                content = opened[0][1]
                if operation == "reveal":
                    self._append("Disclosure", request, call_id, {
                        "decision_id": decision, "subject": values[0].reference.to_dict(),
                        "delivery": "prepared-for-return", "kind": type(content).__name__,
                    })
                    return content
                if operation == "compare":
                    other = opened[1][1] if len(opened) == 2 else parameters[1]
                    answer = {"eq": operator.eq, "lt": operator.lt, "le": operator.le,
                              "gt": operator.gt, "ge": operator.ge}[parameters[0]](content, other)
                    self._append("Observation", request, call_id, {
                        "decision_id": decision, "observation": parameters[0], "value": answer,
                    })
                    return answer
                if operation in {"concat", *BINARY}:
                    if len(opened) == 2:
                        left, right = content, opened[1][1]
                    else:
                        literal, side = parameters
                        left, right = (literal, content) if side == "left" else (content, literal)
                    content = (operator.add if operation == "concat" else BINARY[operation])(left, right)
                elif operation == "upper": content = content.upper()
                elif operation == "lower": content = content.lower()
                elif operation == "strip": content = content.strip(*parameters)
                elif operation == "replace": content = content.replace(*parameters)
                elif operation == "slice": content = content[slice(*parameters)]
                elif operation == "index": content = content[parameters[0]]
                elif operation == "repeat": content *= opened[1][1] if len(opened) == 2 else parameters[0]
                elif operation == "to_int": content = int(content, *parameters)
                elif operation == "to_string": content = str(content)
                elif operation == "negate": content = -content
                elif operation == "positive": content = +content
                elif operation == "absolute": content = abs(content)
                elif operation == "invert": content = ~content
                elif operation == "round": content = round(content, *parameters)
                elif operation in {"trunc", "floor", "ceil"}: content = getattr(math, operation)(content)
                elif operation in {"real", "imag", "numerator", "denominator"}: content = getattr(content, operation)
                elif operation in {"conjugate", "as_integer_ratio", "sqrt", "normalize", "exp", "ln", "log10"}:
                    content = getattr(content, operation)()
                elif operation == "power_mod":
                    args = [opened[arg["input"]][1] if "input" in arg else arg["literal"] for arg in parameters]
                    content = pow(content, *args)
                elif operation == "quantize":
                    exponent = opened[1][1] if len(opened) == 2 else parameters[1]
                    content = content.quantize(exponent, rounding=parameters[0])
                elif operation in {"is_integer", "truth"}:
                    answer = bool(content) if operation == "truth" else content.is_integer()
                    self._append("Observation", request, call_id, {
                        "decision_id": decision, "observation": operation, "value": answer})
                    return answer
            if type(content) is tuple:
                return tuple(self.publish_value(item, request=request, metadata=metadata, actions=(decision,))
                             for item in content)
            return self.publish_value(content, request=request, metadata=metadata, actions=(decision,))
        except Exception as exc:
            self._append("Failure", request, call_id, {"decision_id": decision,
                                                       "error_type": type(exc).__name__})
            raise
