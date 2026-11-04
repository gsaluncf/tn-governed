"""Native governed relations with signed query bindings and positional cell handles."""

from __future__ import annotations

import json
import weakref
from dataclasses import dataclass
from uuid import uuid4

import tn

from tn_governed.native_objects import CarriedPublication, NativeObjects

from .evidence import EvidenceError
from .holders import field_hash
from .primitives import VALUE_TYPE
from .query import SourceColumn, decode_sql, digest, encode_sql
from .query_receipt import QueryTransport, check_result_binding
from .runtime import Request
from .string import MetadataUnavailable, ValueReference

RESULT_SCHEMA = "tn.sql-result.v2"


@dataclass(frozen=True)
class AdmittedQuery:
    """Authorized adapter input; the native object retains its source governance."""

    data: object
    rows: tuple[tuple, ...]
    manifest: dict
    reference: ValueReference
    decision_id: str
    claims: tuple = ()
    actions: tuple = ()


def publish_result(context, rows, binding, *, request, decision_id, query_id):
    """Publish one relation under the full query policy union, including controls."""
    policies = request.policies
    if not policies:
        raise ValueError("query result requires source policies")
    authority = context.session.create({}, policies[0], object_type=VALUE_TYPE, group="values")
    for policy in policies[1:]:
        authority.attach(
            policy, decide=lambda ctx, expected=policy: ctx.policy.matches_contract(expected)
        )
    manifest = {
        "schema": RESULT_SCHEMA,
        "binding": binding,
        "binding_id": digest(binding),
        "decision_id": decision_id,
        "row_count": len(rows.rows),
        "actions": [decision_id] if context.recorder.read(decision_id).body["details"]["obligations"] else [],
    }
    data = authority.policy_output(VALUE_TYPE, {
        "values": {"rows": [[encode_sql(value) for value in row] for row in rows.rows]},
        "evidence": {"manifest": manifest},
    })
    data.bind_manifest("evidence")
    publication = context._release_value(data, request)
    result_id = context._append(
        "Result",
        request,
        query_id,
        {
            "decision_id": decision_id,
            "output": ValueReference(publication.id, "rows", "values").to_dict(),
            "claims": [],
            "field_commitment": field_hash(publication, "values", "rows"),
            "binding_id": manifest["binding_id"],
            "manifest_id": digest(manifest),
            "source": {"query_id": query_id, "schema": RESULT_SCHEMA},
        },
    )
    return publication, result_id, manifest["binding_id"]


@dataclass(frozen=True)
class QueryCell:
    """A result position, distinct even when names, keys or values repeat."""

    result: GovernedQueryResult
    row: int
    column: int

    def reveal(self, destination):
        return self.result._reveal(destination, (self.row, self.column))


class GovernedQueryResult:
    """A transported relation; fetching returns handles, disclosure needs a permit."""

    def __init__(
        self,
        context,
        *,
        object_id,
        decision_id,
        result_id,
        resolution,
        source,
        edition,
        transport,
        publication=None,
    ):
        self._context, self.object_id = weakref.ref(context), object_id
        self.decision_id, self.result_id = decision_id, result_id
        self.resolution, self.source = resolution, json.loads(json.dumps(source))
        self.edition, self.transport = dict(edition), transport
        self._index = 0
        self.publication = publication
        metadata = self.metadata()
        if self.publication is None:
            self.publication = self._carried(context, metadata)
        self.description = tuple(
            (column["name"], None, None, None, None, None, None)
            for column in metadata["binding"]["output_schema"]
        )

    @property
    def context(self):
        context = self._context()
        if context is None:
            raise MetadataUnavailable("query processing requires binding to a receiving context")
        return context

    def _carried(self, context, manifest):
        if manifest["schema"] == RESULT_SCHEMA:
            return CarriedPublication(context.store_object(self.object_id),
                support=(context.store_object(self.decision_id), context.store_object(self.result_id)))
        objects, pending = {}, [self.object_id, self.decision_id, self.result_id]
        while pending:
            identity = pending.pop()
            if identity in objects:
                continue
            if len(objects) >= 65536:
                raise EvidenceError("SQL evidence graph exceeds its transport bound")
            obj = context.store_object(identity)
            objects[identity] = obj
            view = context.session.governance(obj)
            pending.extend(source.object_id for source in view.governance.sources)
        return CarriedPublication(
            objects[self.object_id],
            support=tuple(obj for identity, obj in objects.items() if identity != self.object_id),
        )

    def bind(self, context):
        """Admit the carried native objects under another endpoint's keys and rules."""
        if self.publication.object.id != self.object_id:
            raise EvidenceError("query carrier differs from its signed publication")
        if isinstance(context.recorder.store, NativeObjects):
            context.recorder.store.include(self.publication)
        else:
            for obj in self.publication.objects():
                context.recorder.store.put(obj)
        resolution = context.resolver.resolve_query(
            [
                SourceColumn(item["table"], item["column"], item["database"])
                for item in self.resolution.sources
            ],
            actor=context.actor,
            application=context.application,
            purpose=context.purpose,
            expected_source=self.source,
            packets=self.resolution.packets,
        )
        return type(self)(
            context,
            object_id=self.object_id,
            decision_id=self.decision_id,
            result_id=self.result_id,
            resolution=resolution,
            source=self.source,
            edition=self.edition,
            transport=self.transport,
            publication=self.publication,
        )

    def export(self):
        """Serialize the query's native objects and signed source metadata for transport."""
        if self.publication.object.id != self.object_id:
            raise EvidenceError("query carrier differs from its signed publication")
        wires = {obj.id: obj.forward() for obj in self.publication.objects()}
        return QueryTransport(
            self.object_id,
            self.decision_id,
            self.result_id,
            self.source,
            self.resolution.sources,
            self.resolution.packets,
            self.edition,
            self.transport.edition_wire,
            self.transport.revision_wires,
            tuple(wires[identity] for identity in sorted(wires)),
        )

    @classmethod
    def receive(cls, context, transport):
        """Re-admit carried evidence with the recipient's own keys and authorities."""
        from tn_polars.registry import EditionRegistryEntry

        if not isinstance(transport, QueryTransport):
            raise TypeError("query admission requires QueryTransport")
        for wire in transport.objects:
            context.recorder.store.put(tn.GovernedObject.parse(wire))
        resolution = context.resolver.resolve_query(
            [
                SourceColumn(item["table"], item["column"], item["database"])
                for item in transport.sources
            ],
            actor=context.actor,
            application=context.application,
            purpose=context.purpose,
            expected_source=transport.source,
            packets=transport.packets,
        )
        entry = EditionRegistryEntry(
            transport.edition["dataset"],
            transport.edition["edition"],
            transport.edition["record_id"],
            transport.edition_wire,
            transport.revision_wires,
            {},
        )
        return cls(
            context,
            object_id=transport.object_id,
            decision_id=transport.decision_id,
            result_id=transport.result_id,
            resolution=resolution,
            source=transport.source,
            edition=transport.edition,
            transport=entry,
        )

    def _receive(self, groups, operation):
        context = self.context
        dependencies = tuple(
            SourceColumn(item["table"], item["column"]) for item in self.resolution.sources
        )
        resolution = context.resolver.resolve_query(
            dependencies,
            actor=context.actor,
            application=context.application,
            purpose=context.purpose,
            expected_source=self.source,
            operation="select",
            packets=self.resolution.packets,
        )
        if resolution.sources != self.resolution.sources:
            raise EvidenceError("received query assignments differ from the source binding")
        context.resolver.admit_edition(self.edition, context, transport=self.transport)
        carried = getattr(self, "publication", None)
        obj = carried.object if carried is not None else context.store_object(self.object_id)
        use = tn.UseContext(context.application, context.purpose, operation)
        selection = context.catalog.select(
            self.edition["dataset"], self.edition["edition"], self.edition["record_id"], use
        )
        if (
            selection.record.source_object_id != self.object_id
            or selection.record.grant_ref != "sha256:" + self.edition["edition"]
        ):
            raise EvidenceError("query edition differs from its source and binding digest")
        expected = resolution.policies

        def admit(ctx):
            return (
                context._admit(ctx)
                and len(ctx.policies) == len(expected)
                and all(
                    any(policy.matches_contract(candidate) for candidate in expected)
                    for policy in ctx.policies
                )
                and all(
                    any(policy.matches_contract(candidate) for candidate in ctx.policies)
                    for policy in expected
                )
            )

        return context.session.receive(
            obj, use=use, groups=groups, selection=selection, decide=admit
        )

    def _metadata(self):
        data = self._receive(["evidence"], "inspect-claims")
        manifest = data.get("manifest", group="evidence")
        if (
            not isinstance(manifest, dict)
            or manifest.get("schema") not in {RESULT_SCHEMA, "tn.sql-result.v1"}
            or manifest.get("decision_id") != self.decision_id
            or manifest.get("binding_id") != digest(manifest.get("binding"))
        ):
            raise EvidenceError("query result has an invalid signed binding")
        record = self.context.editions[self.object_id]
        check_result_binding(manifest, sources=list(self.resolution.sources), source=self.source,
                             grant_ref=record.grant_ref)
        self._check_authorized(data, manifest)
        return data, manifest

    def _check_authorized(self, data, manifest):
        """The signed Result and Decision name this publication, its binding, and its manifest."""
        binding = manifest["binding"]
        result = self.context.recorder.read(self.result_id)
        decision = self.context.recorder.read(self.decision_id)
        rb, db = result.body, decision.body
        reference = ValueReference(self.object_id, "rows", "values").to_dict()
        if (
            rb["kind"] != "Result"
            or db["kind"] != "Decision"
            or result.writer != data.snapshot.writer
            or decision.writer != result.writer
            or rb["details"].get("output") != reference
            or rb["details"].get("decision_id") != self.decision_id
            or rb["details"].get("binding_id") != manifest["binding_id"]
            or rb["details"].get("manifest_id") != digest(manifest)
            or db["details"].get("parameters")
            != [{key: value for key, value in binding.items() if key != "output_schema"}]
            or rb["details"].get("field_commitment")
            != field_hash(data.snapshot, "values", "rows")
            or (manifest["schema"] == RESULT_SCHEMA and
                manifest.get("actions") != ([self.decision_id] if db["details"].get("obligations") else []))
            or db["details"].get("permitted") is not True
            or rb["sequence"] <= db["sequence"]
            or any(
                rb[key] != db[key]
                for key in (
                    "context_id",
                    "call_id",
                    "operation",
                    "inputs",
                    "application",
                    "purpose",
                )
            )
        ):
            raise EvidenceError("query result is not bound to its authorized publication")

    def metadata(self):
        return self._metadata()[1]

    @property
    def policies(self):
        return tuple(self._metadata()[0].policies)

    def fetchone(self):
        metadata = self.metadata()
        if self._index >= metadata["row_count"]:
            return None
        row = tuple(QueryCell(self, self._index, column) for column in range(len(self.description)))
        self._index += 1
        return row

    def fetchall(self):
        metadata = self.metadata()
        rows = [
            tuple(QueryCell(self, row, column) for column in range(len(self.description)))
            for row in range(self._index, metadata["row_count"])
        ]
        self._index = metadata["row_count"]
        return rows

    def reveal(self, destination):
        return self._reveal(destination)

    def _opened_rows(self, manifest, operation):
        opened = self._receive(["values"], operation)
        rows = opened.get("rows", group="values")
        schema = manifest["binding"]["output_schema"]
        if (
            not isinstance(rows, list)
            or len(rows) != manifest["row_count"]
            or any(not isinstance(row, list) or len(row) != len(schema) for row in rows)
        ):
            raise EvidenceError("query values differ from the signed result shape")
        try:
            decoded = tuple(tuple(decode_sql(cell) for cell in row) for row in rows)
            canonical = [[encode_sql(value) for value in row] for row in decoded]
        except (TypeError, ValueError, OverflowError) as exc:
            raise EvidenceError("query values have invalid typed encodings") from exc
        if canonical != rows or any(
            sorted({row[column]["kind"] for row in canonical}) != item["storage_types"]
            for column, item in enumerate(schema)
        ):
            raise EvidenceError("query values differ from the signed output schema")
        return opened, decoded

    def open_for_processing(self, operation, destination):
        """Authorize an adapter operation and provide its native governed input."""
        if not isinstance(operation, str) or not operation or operation == "reveal":
            raise ValueError("processing requires a named computational operation")
        if not isinstance(destination, str) or not destination:
            raise ValueError("processing requires a named adapter destination")
        data, manifest = self._metadata()
        reference = ValueReference(self.object_id, "rows", "values")
        request = Request(
            self.context.application,
            self.context.purpose,
            operation,
            (reference,),
            (data.snapshot.writer,),
            tuple(data.policies),
            (),
            destination=destination,
            parameters=(
                manifest["binding"],
                {"selection": "processing", "destination": destination},
            ),
        )
        call_id = uuid4().hex
        decision = self.context._decision(request, call_id)
        try:
            opened, rows = self._opened_rows(manifest, operation)
            self.context._append(
                "Observation",
                request,
                call_id,
                {
                    "decision_id": decision,
                    "binding_id": manifest["binding_id"],
                    "subject": reference.to_dict(),
                    "outcome": "admitted-for-processing",
                },
            )
            actions = list(manifest.get("actions", ()))
            if self.context.recorder.read(decision).body["details"].get("obligations"):
                actions.append(decision)
            return AdmittedQuery(opened, rows, manifest, reference, decision,
                                 tuple(manifest.get("claims", ())), tuple(dict.fromkeys(actions)))
        except Exception as exc:
            self.context._append(
                "Failure",
                request,
                call_id,
                {"decision_id": decision, "error_type": type(exc).__name__},
            )
            raise

    def _reveal(self, destination, position=None):
        data, manifest = self._metadata()
        if position is not None and (
            type(position[0]) is not int
            or type(position[1]) is not int
            or not 0 <= position[0] < manifest["row_count"]
            or not 0 <= position[1] < len(manifest["binding"]["output_schema"])
        ):
            raise IndexError("query cell is outside the signed result shape")
        context, call_id = self.context, uuid4().hex
        reference = ValueReference(self.object_id, "rows", "values")
        request = Request(
            context.application,
            context.purpose,
            "reveal",
            (reference,),
            (data.snapshot.writer,),
            tuple(data.policies),
            (),
            destination=destination,
            parameters=(
                manifest["binding"],
                {"selection": "relation"}
                if position is None
                else {"selection": "cell", "row": position[0], "column": position[1]},
            ),
        )
        decision = context._decision(request, call_id)
        try:
            _, decoded = self._opened_rows(manifest, "reveal")
            value = list(decoded) if position is None else decoded[position[0]][position[1]]
            context._append(
                "Disclosure",
                request,
                call_id,
                {
                    "decision_id": decision,
                    "subject": reference.to_dict(),
                    "position": None if position is None else list(position),
                    "delivery": "prepared-for-return",
                    "binding_id": manifest["binding_id"],
                },
            )
            return value
        except Exception as exc:
            context._append(
                "Failure",
                request,
                call_id,
                {"decision_id": decision, "error_type": type(exc).__name__},
            )
            raise
