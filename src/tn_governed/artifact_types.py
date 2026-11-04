"""Portable artifact handles and transfer bundles, and the manifest shape an artifact signs."""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from .native_objects import CarriedPublication
from .values.evidence import EvidenceError
from .values.string import ValueReference

ARTIFACT_TYPE = "tn.artifact"
ARTIFACT_SCHEMA = "tn.artifact.v2"
MANIFEST_GROUP = "evidence"
_MANIFEST_LISTS = ("claims", "disputes", "action_records")
_MANIFEST_FIELDS = {"schema", "operation", "parameters", "destination", "decision_id", "state",
                    *_MANIFEST_LISTS}


def artifact_json(value, depth=0):
    """`value` as ordinary finite JSON with string keys; anything else is refused."""
    if depth > 128:
        raise ValueError("JSON nesting exceeds the artifact limit")
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    if type(value) in (list, tuple):
        return [artifact_json(item, depth + 1) for item in value]
    if type(value) is dict and all(type(key) is str for key in value):
        return {key: artifact_json(item, depth + 1) for key, item in value.items()}
    raise TypeError("artifact data requires ordinary finite JSON values with string keys")


def check_manifest(manifest, decision_id):
    """The manifest has exactly the artifact schema's fields and names its producing Decision."""
    if (
        not isinstance(manifest, dict)
        or (manifest.get("schema"), set(manifest)) not in (
            (ARTIFACT_SCHEMA, _MANIFEST_FIELDS),
            ("tn.artifact.v1", _MANIFEST_FIELDS | {"parents", "external_inputs"}),
        )
        or manifest["decision_id"] != decision_id
        or manifest["state"] not in {"active", "deleted"}
        or not isinstance(manifest["parameters"], dict)
        or any(not isinstance(manifest[key], list) for key in _MANIFEST_LISTS)
    ):
        raise EvidenceError("artifact manifest is invalid")


@dataclass(frozen=True)
class GovernedArtifact:
    reference: ValueReference
    decision_id: str | None = None
    result_id: str | None = None
    carrier: CarriedPublication | None = field(default=None, compare=False, hash=False, repr=False)

    def __post_init__(self):
        from .publications import object_digest

        if not isinstance(self.reference, ValueReference):
            raise TypeError("an artifact requires a native value reference")
        if self.reference.group != "values" or self.reference.field != "value":
            raise ValueError("artifact references must select values.value")
        if self.decision_id is not None or self.result_id is not None:
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
