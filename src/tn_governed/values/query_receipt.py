"""What a recipient checks: the SQL transport container and the signed source policy assignments."""

from __future__ import annotations

import json
from dataclasses import dataclass

from .evidence import EvidenceError
from .query import decode_sql, encode_sql


def check_result_binding(manifest, *, sources, source, grant_ref):
    """The signed binding names the admitted sources, snapshot, and edition, with a valid lineage."""
    binding = manifest["binding"]
    if (
        not isinstance(binding, dict)
        or binding.get("sources") != sources
        or binding.get("snapshot") != source
        or manifest["binding_id"] != grant_ref
        or type(manifest.get("row_count")) is not int
        or manifest["row_count"] < 0
    ):
        raise EvidenceError("query result differs from the admitted source assignments")
    _check_output_schema(binding.get("output_schema"))
    if manifest["schema"] == "tn.sql-result.v2":
        if (set(binding) != {"schema", "query_id", "snapshot", "sources", "output_schema"}
                or binding["schema"] != "tn.sql-query.v2"):
            raise EvidenceError("invalid signed SQL policy binding")
        return
    # Previously issued v1 objects carried additional signed lineage.
    lineage = manifest.get("lineage")
    if (
        binding.get("schema") != "tn.sql-query.v1"
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
    verify_lineage(manifest)


def _check_output_schema(schema):
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


def _verify_row_key(key):
    if not isinstance(key, list) or not key or [encode_sql(decode_sql(v)) for v in key] != key:
        raise EvidenceError("query lineage has an invalid row identity")


def _verify_contributor_rows(manifest, lineage, sources):
    """Check shared row identities against the result shape and assigned sources."""
    rows, columns = lineage["contributor_rows"], lineage["contributor_columns"]
    width = len(rows[0]) if rows else 0
    if (len(rows) != manifest["row_count"]
            or len(columns) != len(manifest["binding"]["output_schema"])
            or any(len(row) != width for row in rows)):
        raise EvidenceError("query lineage does not cover its result positions")
    for item in (source for column in columns for source in column):
        if ("main", item["table"], item["column"]) not in sources or item["role"] not in {
            "value", "control", "presence",
        }:
            raise EvidenceError("query lineage names an unassigned contributor")
        index = item["identity"]
        if index is not None and (type(index) is not int or (rows and not 0 <= index < width)):
            raise EvidenceError("query lineage has an invalid row identity")
    for member in (item for row in rows for members in row for item in members):
        if type(member) is not int:
            _verify_row_key(json.loads(member))


def verify_lineage(manifest):
    """A signed query lineage covers its result positions and names only assigned sources."""
    binding, lineage = manifest["binding"], manifest["lineage"]
    sources = {(item["database"], item["table"], item["column"]) for item in binding["sources"]}
    try:
        if {
            (item["database"], item["table"], item["column"]) for item in lineage["source_columns"]
        } != sources:
            raise EvidenceError("query lineage source scope differs from its assigned sources")
        if "contributor_rows" in lineage:
            _verify_contributor_rows(manifest, lineage, sources)
            return
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
            if key is not None:
                _verify_row_key(key)
            if lineage["precision"] == "exact" and key is None:
                raise EvidenceError("exact query lineage requires contributor identities")
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, EvidenceError):
            raise
        raise EvidenceError("malformed query lineage") from exc


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
