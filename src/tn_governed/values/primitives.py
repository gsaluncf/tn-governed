"""Application execution for governed Python primitives over the pinned native TN SDK."""

from dataclasses import replace
import operator
import math
import os
from uuid import uuid4
import weakref
from typing import NamedTuple

import tn

from tn_governed.native_objects import CarriedPublication

from .evidence import EvidenceError
from .holders import holder, suppliers
from .manifests import (BATCH_SCHEMA, POLICY_SCHEMA, SCHEMA, SCHEMAS, ColumnBindings, SharedPolicyBindings,
                        column_manifest_from_columns, column_manifest_from_facts, result_names,
                        shared_policy_manifest, signed_manifest)
from .numeric import TNNumeric
from .numeric_codec import KINDS, NUMERIC_TYPES, encode, decode, record_value
from .metadata import DeclaredMetadata, column_facts, describe
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


def columns_enabled():
    """Column batches and column manifests are the default; ``TN_COLUMNS=0`` selects per-cell handling."""
    return os.environ.get("TN_COLUMNS", "1") != "0"


class ColumnBatch(NamedTuple):
    """Consecutive source cells of one column, published as one object under one signed manifest."""
    object_id: str
    names: tuple
    kind: str
    first_row: int
    publication: CarriedPublication | None
    metadata_provider: object

    @property
    def size(self):
        return len(self.names)

    def reference(self, index):
        return _trusted_reference(self.object_id, self.names[index], "values")

    def handle(self, index):
        return _PrimitiveHandle(self.reference(index), None, None, self.kind, self.publication,
                                self.metadata_provider)

    def with_publication(self, publication):
        return self._replace(publication=publication)


class _ColumnInputs:
    """The ordered input references of batches and single cells, built only when iterated."""

    def __init__(self, batches, cells):
        self._batches, self._cells = tuple(batches), tuple(cells)

    def __len__(self):
        return sum(batch.size for batch in self._batches) + len(self._cells)

    def __iter__(self):
        for batch in self._batches:
            for index in range(batch.size):
                yield batch.reference(index)
        for cell in self._cells:
            yield cell.reference


def _trusted_reference(object_id, field, group):
    """A reference to a field this endpoint just generated, without re-validating its names."""
    reference = object.__new__(ValueReference)
    object.__setattr__(reference, "object_id", object_id)
    object.__setattr__(reference, "field", field)
    object.__setattr__(reference, "group", group)
    return reference


class _PrimitiveHandle(NamedTuple):
    reference: ValueReference
    decision_id: str | None
    result_id: str | None
    kind: str
    publication: CarriedPublication | None
    metadata_provider: object

    def materialize(self):
        cls = TNString if self.kind == "str" else TNNumeric
        return cls(self.reference, self.decision_id, self.result_id,
                   metadata_provider=self.metadata_provider, publication=self.publication)


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
        # Opt-in: sign the facts every cell of a source batch shares once and the rest as columns.
        self.column_batches = columns_enabled()
        self.share_manifest_facts = self.column_batches or os.environ.get("TN_SHARE_MANIFEST_FACTS") == "1"
        # Parsed signed manifests by object ID. A stored object never changes, so its manifest
        # is parsed once; every read still passes this endpoint's receive and admission check.
        self._parsed_manifests = {}
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

    def hydrate_many(self, handles, *, _lazy=False):
        handles = tuple(handles)
        kinds = {"str", *KINDS}
        values = (self._lazy_handles(handles, kinds) if _lazy and self.share_manifest_facts else [])
        for handle in (() if values else handles):
            if len(handle) not in (4, 5):
                raise ValueError("received handles require four fields and optional native material")
            reference, decision_id, result_id, kind = handle[:4]
            carried = handle[4] if len(handle) == 5 else None
            if kind not in kinds:
                raise TypeError("unsupported primitive kind")
            cls = TNString if kind == "str" else TNNumeric
            if _lazy:
                if not isinstance(reference, ValueReference):
                    raise TypeError("received primitive requires a native field reference")
                if carried is not None and (not isinstance(carried, CarriedPublication)
                        or carried.identity != reference.object_id):
                    raise ValueError("carried publication differs from the value reference")
                values.append(_PrimitiveHandle(reference, decision_id, result_id, kind,
                                                carried, self.string_metadata))
            else:
                values.append(cls(reference, decision_id, result_id, metadata_provider=self.string_metadata,
                                  publication=carried))
        metadata = self._metadata_many(values)
        shared, keys, carriers = {}, {}, {}
        for index, ((_, binding, _), handle) in enumerate(zip(metadata, handles, strict=True)):
            if binding["declared"]["kind"] != handle[3]:
                raise EvidenceError("requested type differs from signed primitive kind")
            value = values[index]
            if value.reference.object_id in self.editions and "parents" not in binding:
                # Cells of one column batch share their signed support lists; key them once.
                memo = value.reference.object_id, id(binding["claims"]), id(binding["actions"])
                key = keys.get(memo)
                if key is None:
                    key = keys[memo] = (value.reference.object_id, tuple(binding["claims"]),
                                        tuple(binding["actions"]))
                if key not in shared:
                    shared[key] = self._policy_carrier(self.store_object(value.reference.object_id), binding)
                carrier = shared[key]
            elif value.publication is None:
                carrier = self._received_carrier(value, binding, shared=shared)
            else:
                continue
            identity = carriers.get(id(carrier))
            if identity is None:
                if not isinstance(carrier, CarriedPublication):
                    raise ValueError("carried publication differs from the value reference")
                identity = carriers[id(carrier)] = carrier.identity
            if identity != value.reference.object_id:
                raise ValueError("carried publication differs from the value reference")
            # These wrappers are private to hydration until their checked carriers are attached.
            if isinstance(value, _PrimitiveHandle):
                values[index] = _PrimitiveHandle(value.reference, value.decision_id, value.result_id,
                                                 value.kind, carrier, value.metadata_provider)
            else:
                object.__setattr__(value, "publication", carrier)
        return tuple(values)

    def _lazy_handles(self, handles, kinds):
        """The lazy handle checks of ``hydrate_many``, each carrier's identity read once."""
        values, carriers, provider = [], {}, self.string_metadata
        append = values.append
        for handle in handles:
            size = len(handle)
            if size != 4 and size != 5:
                raise ValueError("received handles require four fields and optional native material")
            reference, decision_id, result_id, kind = handle[0], handle[1], handle[2], handle[3]
            carried = handle[4] if size == 5 else None
            if kind not in kinds:
                raise TypeError("unsupported primitive kind")
            if not isinstance(reference, ValueReference):
                raise TypeError("received primitive requires a native field reference")
            if carried is not None:
                identity = carriers.get(id(carried))
                if identity is None:
                    if not isinstance(carried, CarriedPublication):
                        raise ValueError("carried publication differs from the value reference")
                    identity = carriers[id(carried)] = carried.identity
                if identity != reference.object_id:
                    raise ValueError("carried publication differs from the value reference")
            append(_PrimitiveHandle(reference, decision_id, result_id, kind, carried, provider))
        return values

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
        manifest = self._parsed_manifests.get(value.reference.object_id) if self.share_manifest_facts else None
        if manifest is None:
            manifest = signed_manifest(data)
            if self.share_manifest_facts and isinstance(manifest, dict) and isinstance(
                    manifest.get("bindings"), (SharedPolicyBindings, ColumnBindings)):
                self._parsed_manifests[value.reference.object_id] = manifest
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

    def _shared_support(self, bindings, records):
        """Check the claims and actions a shared manifest signs once for all its cells."""
        claims, actions = bindings.shared["claims"], bindings.shared["actions"]
        if not isinstance(claims, list) or not isinstance(actions, list):
            raise EvidenceError("invalid signed policy-bearing value")
        self._action_support(actions, records)
        checked = []
        for identity in claims:
            claim = self._record(identity, records)
            if (claim.body["kind"] != "Claim" or not isinstance(claim.body["details"].get("statement"), str)
                    or not claim.body["details"]["statement"].strip() or not claim.body["inputs"]):
                raise EvidenceError("invalid signed claim")
            checked.append(Claim(identity, claim.writer,
                                 tuple(ValueReference(**r) for r in unpack_references(claim.body["inputs"])),
                                 claim.body["details"]["statement"]))
        return tuple(checked)

    def _shared_metadata_fields(self, values, data, bindings, envelope, records):
        """Check the support a shared manifest signs once, then only each cell's own facts."""
        checked = self._shared_support(bindings, records)
        hashes, result = envelope["values"]["field_hashes"], []
        for value in values:
            reference = value.reference
            binding = bindings.get(reference.field)
            if binding is None:
                raise EvidenceError("missing signed primitive binding")
            kind = binding["declared"].get("kind")
            if not (kind == value.kind if type(value) is _PrimitiveHandle else
                    kind in KINDS if isinstance(value, TNNumeric) else kind == "str"):
                raise EvidenceError("primitive class differs from signed logical kind")
            if (value.decision_id is not None or value.result_id is not None
                    or reference.group != "values" or reference.field not in hashes):
                raise EvidenceError("invalid signed policy-bearing value")
            result.append((data, binding, checked))
        return result

    def _metadata_fields(self, values, data, manifest, writer, envelope, records):
        if not isinstance(manifest, dict) or manifest.get("schema") not in SCHEMAS:
            raise EvidenceError("missing signed primitive manifest")
        bindings = manifest.get("bindings", {})
        if self.share_manifest_facts and isinstance(bindings, (SharedPolicyBindings, ColumnBindings)):
            return self._shared_metadata_fields(values, data, bindings, envelope, records)
        policy_schema = manifest["schema"] == POLICY_SCHEMA
        result = []
        for value in values:
            binding = bindings.get(value.reference.field)
            if not isinstance(binding, dict):
                raise EvidenceError("missing signed primitive binding")
            expected_kinds = ({value.kind} if isinstance(value, _PrimitiveHandle) else
                              KINDS if isinstance(value, TNNumeric) else {"str"})
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

    def _open_values(self, request, values, *, metadata=None, _columns=None):
        if metadata is not None and (
                not isinstance(metadata, _CheckedMetadata) or metadata.context is not self
                or metadata.references != tuple(value.reference for value in values)):
            raise EvidenceError("prepared metadata differs from this context or its ordered inputs")
        if _columns is not None and metadata is not None and self.share_manifest_facts:
            return self._open_columns(request, values, metadata, _columns)
        result, opened = ([] if _columns is None else {name: [] for name in _columns}), {}
        first_data = None
        for index, value in enumerate(values):
            key = value.reference.object_id, value.reference.group
            if key not in opened:
                groups = [value.reference.group] if metadata is not None else [value.reference.group, "evidence"]
                data = self._read(value, groups, request.operation)
                manifest = signed_manifest(data) if metadata is None else metadata.manifests[key]
                opened[key] = data, manifest, data.get(None, group=value.reference.group)
            data, manifest, payloads = opened[key]
            payload = payloads[value.reference.field]
            facts = manifest["bindings"][value.reference.field]["declared"]
            content = decode(payload, facts["kind"])
            if describe(content) != facts:
                raise EvidenceError("declared facts do not match the opened content")
            if _columns is None:
                result.append((data, content))
            else:
                if first_data is None:
                    first_data = data
                result[_columns[index % len(_columns)]].append(content)
        return result if _columns is None else (first_data, result)

    def _open_columns(self, request, values, metadata, columns):
        """Open each batch once, in first-use order, and check every cell's facts against its content."""
        order, contents, first_data = {}, [None] * len(values), None
        for index, value in enumerate(values):
            order.setdefault((value.reference.object_id, value.reference.group), []).append(index)
        for key, indices in order.items():
            data = self._read(values[indices[0]], [key[1]], request.operation)
            if first_data is None:
                first_data = data
            bindings, payloads = metadata.manifests[key]["bindings"], data.get(None, group=key[1])
            fields = [values[index].reference.field for index in indices]
            declared = [bindings[field]["declared"] for field in fields]
            opened = [decode(payloads[field], facts["kind"]) for field, facts in zip(fields, declared)]
            if list(map(describe, opened)) != declared:
                raise EvidenceError("declared facts do not match the opened content")
            for index, content in zip(indices, opened):
                contents[index] = content
        return first_data, {name: contents[i::len(columns)] for i, name in enumerate(columns)}

    def _batch_metadata(self, batch, records):
        """Admit one source batch: one signed-evidence read, one support check, column-wide cell checks."""
        data, manifest, writer, envelope = self._metadata_read(batch.handle(0))
        bindings = manifest.get("bindings") if isinstance(manifest, dict) else None
        if not isinstance(bindings, ColumnBindings) or manifest.get("schema") != POLICY_SCHEMA:
            raise EvidenceError("a column batch requires its signed column manifest")
        checked = self._shared_support(bindings, records)
        kinds = bindings.column("kind")
        if kinds.count(batch.kind) != len(kinds):
            raise EvidenceError("primitive class differs from signed logical kind")
        names = set(batch.names)
        if not names <= set(bindings.fields) or not names <= envelope["values"]["field_hashes"].keys():
            raise EvidenceError("missing signed primitive binding")
        support = {"claims": bindings.shared["claims"], "actions": bindings.shared["actions"]}
        return data, support, checked, manifest, writer

    def admit_columns(self, batches):
        """Receive whole source batches; each carries this endpoint's checked carrier."""
        batches = tuple(batches)
        self._adopt(tuple(batch.handle(0) for batch in batches))
        records, admitted = {}, []
        for batch in batches:
            data, support, _, _, _ = self._batch_metadata(batch, records)
            if batch.object_id in self.editions:
                carrier = self._policy_carrier(self.store_object(batch.object_id), support)
            else:
                carrier = self._received_carrier(batch.handle(0), {**support, "declared": {}}, shared={})
            if not isinstance(carrier, CarriedPublication) or carrier.identity != batch.object_id:
                raise ValueError("carried publication differs from the value reference")
            admitted.append(batch.with_publication(carrier))
        return tuple(admitted)

    def _prepare_columns(self, operation, batches, cells, call_id):
        """``_prepare`` for whole batches plus individual cells: admission once per publication."""
        inputs = _ColumnInputs(batches, cells)
        base = Request(self.application, self.purpose, operation, inputs, (), (), ())
        try:
            self._adopt(tuple(batch.handle(0) for batch in batches))
            records, items = {}, {}
            for batch in batches:
                data, support, checked, manifest, writer = self._batch_metadata(batch, records)
                items[batch.object_id] = (data, support, checked, manifest, writer)
            cell_items = self._metadata_many(cells) if cells else []
        except Exception as exc:
            decision = self._append("Decision", base, call_id, {
                "permitted": False, "reason": "input admission failed", "error_type": type(exc).__name__})
            self._append("Refusal", base, call_id, {"decision_id": decision, "reason": "input admission failed"})
            raise OperationDenied(f"input admission failed: {type(exc).__name__}") from exc
        claims, policies, writers = {}, [], []
        sources = [(data, checked, writer) for data, _, checked, _, writer in items.values()]
        sources += [(data, checked, data.snapshot.writer) for data, _, checked in cell_items]
        for data, checked, writer in sources:
            claims.update((claim.id, claim) for claim in checked)
            writers.append(writer)
            for policy in data.policies:
                if not any(policy.matches_contract(existing) for existing in policies):
                    policies.append(policy)
        request = replace(base, writers=tuple(writers), policies=tuple(policies), claims=tuple(claims.values()))
        return request, items, cell_items, self._decision(request, call_id, record_permit=False)

    def _open_batch(self, request, batch, item):
        """Open one batch once and check every cell's signed facts against its content."""
        data = self._read(batch.handle(0), ["values"], request.operation)
        payloads, bindings = data.get(None, group="values"), item[3]["bindings"]
        values = [payloads[name] for name in batch.names]
        contents = values if batch.kind == "str" else [decode(value, batch.kind) for value in values]
        facts = column_facts(contents)
        if facts is None or set(facts) != set(bindings.fact_names()):
            raise EvidenceError("declared facts do not match the opened content")
        if list(batch.names) == list(bindings.fields):
            mismatch = any(bindings.column(key) != column for key, column in facts.items())
        else:
            position = {name: index for index, name in enumerate(bindings.fields)}
            indices = [position[name] for name in batch.names]
            mismatch = any([bindings.column(key)[index] for index in indices] != column
                           for key, column in facts.items())
        if mismatch:
            raise EvidenceError("declared facts do not match the opened content")
        return data, contents

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

    def originate_batch(self, cells, policy, *, request, decision_id, call_id, _handles=False):
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
        return self._source_fields(fields, facts, policy, request, decision_id, call_id, _handles=_handles)

    def originate(self, content, policy, *, source, request, decision_id, call_id):
        return self._source_fields({"value": encode(content)}, {"value": describe(content)},
                                   policy, request, decision_id, call_id)[0]

    def _source_support(self, policy, request, decision_id, call_id):
        """The claims and actions a source batch carries, under this query's signed permit."""
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
        return {"claims": claims, "actions": [decision_id] if details.get("obligations") else []}

    def _release_source(self, fields, manifest, policy, request, support):
        seed = self.session.create({}, policy, object_type=VALUE_TYPE, group="values")
        data = seed.policy_output(VALUE_TYPE, {"values": fields, "evidence": {"manifest": manifest}})
        data.bind_manifest("evidence")
        publication = self._release_value(data, replace(request, policies=(policy,)))
        return publication, self._policy_carrier(publication, support)

    def originate_column(self, contents, policy, *, first_row, request, decision_id, call_id):
        """Publish consecutive cells of one column as one batch with signed fact columns.

        Returns None for column types without a column fact path; the caller publishes cells.
        """
        contents = list(contents)
        if not contents or len(contents) > MAX_SOURCE_PUBLICATION_CELLS:
            raise ValueError(
                f"source publication requires between 1 and {MAX_SOURCE_PUBLICATION_CELLS} cells")
        columns = column_facts(contents)
        if columns is None:
            return None
        support = self._source_support(policy, request, decision_id, call_id)
        names = [f"value_{row}" for row in range(first_row, first_row + len(contents))]
        payloads = contents if columns["kind"][0] == "str" else list(map(str, contents))
        manifest = column_manifest_from_columns(names, columns, support["claims"], support["actions"])
        publication, carrier = self._release_source(dict(zip(names, payloads)), manifest, policy, request, support)
        ValueReference(publication.id, names[0], "values")  # the object ID is checked once
        return ColumnBatch(publication.id, tuple(names), columns["kind"][0], first_row, carrier,
                           self.string_metadata)

    def _source_fields(self, fields, facts, policy, request, decision_id, call_id, *, _handles=False):
        """Bind each field to the source rules under this endpoint's signed query admission."""
        support = self._source_support(policy, request, decision_id, call_id)
        manifest = (column_manifest_from_facts(facts, support["claims"], support["actions"])
                    if self.share_manifest_facts else None)
        if manifest is None:
            bindings = {field: {"declared": declared, **support} for field, declared in facts.items()}
            manifest = {"schema": POLICY_SCHEMA, "bindings": bindings}
            if self.share_manifest_facts:
                manifest = shared_policy_manifest(bindings) or manifest
        publication, carrier = self._release_source(fields, manifest, policy, request, support)
        cls = TNString if next(iter(facts.values()))["kind"] == "str" else TNNumeric
        identity = publication.id
        # SQL hands references directly to its receiver; only that endpoint needs wrappers.
        if _handles and self.share_manifest_facts:
            # The object ID is checked once; field names here are generated by this endpoint.
            ValueReference(identity, next(iter(fields)), "values")
            return tuple((_trusted_reference(identity, field, "values"), None, None,
                          facts[field]["kind"], carrier) for field in fields)
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
