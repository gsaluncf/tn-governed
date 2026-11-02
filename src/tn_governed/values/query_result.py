"""Native governed relations with signed query bindings and positional cell handles."""

from __future__ import annotations

import json
import weakref
from dataclasses import dataclass
from uuid import uuid4

import tn

from tn_governed.native_objects import CarriedPublication, NativeObjects

from .evidence import EvidenceError
from .primitives import VALUE_TYPE
from .query import SourceColumn, decode_sql, digest, encode_sql
from .runtime import Request
from .string import MetadataUnavailable, ValueReference

RESULT_SCHEMA = "tn.sql-result.v1"


def _verify_lineage(manifest):
    binding, lineage = manifest["binding"], manifest["lineage"]
    sources = {(item["database"], item["table"], item["column"]) for item in binding["sources"]}
    try:
        if {
            (item["database"], item["table"], item["column"]) for item in lineage["source_columns"]
        } != sources:
            raise EvidenceError("query lineage source scope differs from its assigned sources")
        positions = set()
        for cell in lineage["cells"]:
            position = cell["row"], cell["column"]
            if (
                any(type(item) is not int for item in position)
                or not 0 <= position[0] < manifest["row_count"]
                or not 0 <= position[1] < len(binding["output_schema"])
                or position in positions
            ):
                raise EvidenceError("query lineage has an invalid result position")
            positions.add(position)
        expected_positions = {
            (row, column)
            for row in range(manifest["row_count"])
            for column in range(len(binding["output_schema"]))
        }
        if (
            lineage["cells"] or lineage["row_support"] in {"known", "partial"}
        ) and positions != expected_positions:
            raise EvidenceError("query lineage does not cover its result positions")
        for item in [
            *lineage["controls"],
            *(contributor for cell in lineage["cells"] for contributor in cell["contributors"]),
        ]:
            if ("main", item["table"], item["column"]) not in sources or item["role"] not in {
                "value",
                "control",
                "presence",
            }:
                raise EvidenceError("query lineage names an unassigned contributor")
            key = item["row_key"]
            if key is not None and (
                not isinstance(key, list)
                or not key
                or [encode_sql(decode_sql(value)) for value in key] != key
            ):
                raise EvidenceError("query lineage has an invalid row identity")
            if lineage["precision"] == "exact" and key is None:
                raise EvidenceError("exact query lineage requires contributor identities")
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, EvidenceError):
            raise
        raise EvidenceError("malformed query lineage") from exc


@dataclass(frozen=True)
class AdmittedQuery:
    """Authorized adapter input; the native object retains its source governance."""

    data: object
    rows: tuple[tuple, ...]
    manifest: dict
    reference: ValueReference
    decision_id: str
    claims: tuple = ()


@dataclass(frozen=True)
class QueryTransport:
    """Transport container for canonical TN wires; it grants no authority."""

    object_id: str
    decision_id: str
    result_id: str
    source: dict
    sources: tuple
    packets: tuple
    edition: dict
    edition_wire: bytes
    revision_wires: tuple
    objects: tuple[bytes, ...]

    def to_bytes(self):
        return json.dumps(
            {
                "schema": "tn.sql-transport.v1",
                "object_id": self.object_id,
                "decision_id": self.decision_id,
                "result_id": self.result_id,
                "source": self.source,
                "sources": self.sources,
                "edition": self.edition,
                "edition_wire": self.edition_wire.decode("utf-8"),
                "revision_wires": [
                    (identity, wire.decode("utf-8")) for identity, wire in self.revision_wires
                ],
                "packets": [
                    {
                        "table": table,
                        "assignment_wire": packet.assignment_wire.decode("utf-8"),
                        "revision_wires": [
                            (identity, wire.decode("utf-8"))
                            for identity, wire in packet.revision_wires
                        ],
                        "unity_volume_id": packet.unity_volume_id,
                    }
                    for table, packet in self.packets
                ],
                "objects": [wire.decode("utf-8") for wire in self.objects],
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @classmethod
    def from_bytes(cls, wire):
        from .catalog import ResolutionPacket

        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise EvidenceError("duplicate SQL transport field")
                value[key] = item
            return value

        body = json.loads(wire, object_pairs_hook=unique)
        required = {
            "schema",
            "object_id",
            "decision_id",
            "result_id",
            "source",
            "sources",
            "packets",
            "edition",
            "edition_wire",
            "revision_wires",
            "objects",
        }
        if (
            not isinstance(body, dict)
            or set(body) != required
            or body["schema"] != "tn.sql-transport.v1"
        ):
            raise EvidenceError("invalid SQL transport schema")
        if not isinstance(body["objects"], list) or len(body["objects"]) > 65536:
            raise EvidenceError("invalid SQL transport object set")
        return cls(
            body["object_id"],
            body["decision_id"],
            body["result_id"],
            body["source"],
            tuple(body["sources"]),
            tuple(
                (
                    item["table"],
                    ResolutionPacket(
                        item["assignment_wire"].encode("utf-8"),
                        tuple(
                            (identity, value.encode("utf-8"))
                            for identity, value in item["revision_wires"]
                        ),
                        item["unity_volume_id"],
                    ),
                )
                for item in body["packets"]
            ),
            body["edition"],
            body["edition_wire"].encode("utf-8"),
            tuple((identity, value.encode("utf-8")) for identity, value in body["revision_wires"]),
            tuple(value.encode("utf-8") for value in body["objects"]),
        )


def publish_result(context, rows, binding, lineage, *, request, decision_id, query_id):
    """Publish one relation under the full query policy union, including controls."""
    policies = request.policies
    if not policies:
        raise ValueError("query result requires source policies")
    # Native creation seals a retained ancestor. Business content is added only
    # after every value and control dependency's contract has been attached.
    data = context.session.create({}, policies[0], object_type=VALUE_TYPE, group="values")
    context.recorder.store.put(data.snapshot)
    for policy in policies[1:]:
        data.attach(
            policy, decide=lambda ctx, expected=policy: ctx.policy.matches_contract(expected)
        )
    data.set("rows", [[encode_sql(value) for value in row] for row in rows.rows], group="values")
    manifest = {
        "schema": RESULT_SCHEMA,
        "binding": binding,
        "binding_id": digest(binding),
        "decision_id": decision_id,
        "row_count": len(rows.rows),
        "lineage": lineage,
    }
    data.set(None, {"manifest": manifest}, group="evidence")
    publication = context._release_value(data, request)
    result_id = context._append(
        "Result",
        request,
        query_id,
        {
            "decision_id": decision_id,
            "output": ValueReference(publication.id, "rows", "values").to_dict(),
            "claims": [],
            "field_commitment": publication.envelope["values"]["field_hashes"]["rows"],
            "binding_id": manifest["binding_id"],
            "manifest_id": digest(manifest),
            "transition": {"governed_inputs": [], "retained_claims": [], "literal_inputs": []},
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
            self.publication = self._carried(context)
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

    def _carried(self, context):
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
            if obj.object_type == "experiment.evidence":
                record = context.recorder.read(identity)
                if record.body["previous"] is not None:
                    pending.append(record.body["previous"])
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
            or manifest.get("schema") != RESULT_SCHEMA
            or manifest.get("decision_id") != self.decision_id
            or manifest.get("binding_id") != digest(manifest.get("binding"))
        ):
            raise EvidenceError("query result has an invalid signed binding")
        binding = manifest["binding"]
        lineage = manifest.get("lineage")
        record = self.context.editions[self.object_id]
        if (
            not isinstance(binding, dict)
            or binding.get("schema") != "tn.sql-query.v1"
            or binding.get("sources") != list(self.resolution.sources)
            or binding.get("snapshot") != self.source
            or manifest["binding_id"] != record.grant_ref
            or not isinstance(lineage, dict)
            or binding.get("lineage_precision") not in {"exact", "conservative"}
            or binding["lineage_precision"] != lineage.get("precision")
            or binding.get("lineage_provider") != lineage.get("provider")
            or lineage.get("row_support") not in {"known", "partial", "unknown"}
            or (binding["lineage_precision"] == "exact" and lineage["row_support"] != "known")
            or type(manifest.get("row_count")) is not int
            or manifest["row_count"] < 0
        ):
            raise EvidenceError("query result differs from the admitted source assignments")
        schema = binding.get("output_schema")
        if (
            not isinstance(schema, list)
            or not schema
            or any(
                not isinstance(column, dict)
                or column.get("position") != index
                or type(column.get("position")) is not int
                or not isinstance(column.get("name"), str)
                or not isinstance(column.get("storage_types"), list)
                for index, column in enumerate(schema)
            )
        ):
            raise EvidenceError("query result requires an indexed output schema")
        _verify_lineage(manifest)
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
            != data.snapshot.envelope["values"]["field_hashes"]["rows"]
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
        return data, manifest

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
            return AdmittedQuery(
                opened, rows, manifest, reference, decision, tuple(manifest.get("claims", ()))
            )
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
