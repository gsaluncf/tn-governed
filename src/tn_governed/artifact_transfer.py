"""Bounded native closures of artifacts: carriers between endpoints, export, and admitted transfer."""

from __future__ import annotations

from dataclasses import replace

import tn

from .artifact_types import ARTIFACT_TYPE, MANIFEST_GROUP, ArtifactBundle, GovernedArtifact
from .artifact_verification import verify_artifact
from .native_objects import CarriedPublication, NativeObjects, include_carrier
from .values.evidence import EVIDENCE_TYPE, EvidenceError
from .values.references import unpack_references


def closure(endpoint, artifact, *, max_objects=10000, stop_ids=()):
    """The artifact's publication, its native sources, and every record its evidence names."""
    pending = [artifact.reference.object_id, artifact.decision_id, artifact.result_id]
    stopped, visited = set(stop_ids), {}
    while pending:
        identity = pending.pop()
        if identity in visited or identity in stopped:
            continue
        if len(visited) >= max_objects:
            raise EvidenceError("artifact closure exceeds the configured object limit")
        obj = endpoint.store.read(identity)
        visited[identity] = obj
        pending.extend(source.object_id for source in endpoint.session.governance(obj).governance.sources)
        if obj.object_type == ARTIFACT_TYPE and MANIFEST_GROUP in obj.envelope:
            pending.extend(_manifest_references(endpoint, obj))
        elif obj.object_type == EVIDENCE_TYPE:
            pending.extend(_record_references(endpoint._record(identity)))
    return visited


def _manifest_references(endpoint, obj):
    data = endpoint.session.receive(obj, use=endpoint.inspect_use, groups=[MANIFEST_GROUP],
                                    decide=endpoint._admit)
    manifest = data.get("manifest", group=MANIFEST_GROUP)
    if not manifest:
        return []
    references = [manifest["decision_id"], *manifest["claims"], *manifest["action_records"]]
    references.extend(item["object_id"] for item in manifest["external_inputs"])
    for parent in manifest["parents"]:
        handle = GovernedArtifact.from_dict(parent)
        references.extend([handle.reference.object_id, handle.decision_id, handle.result_id])
    return references


def _record_references(record):
    """A record's required-action observations and inputs; its chain predecessor is not followed."""
    references = []
    if record.body["kind"] == "Decision":
        references.extend(record.body["details"].get("action_progress", ()))
    references.extend(item["object_id"] for item in unpack_references(record.body["inputs"]))
    return references


def carried(endpoint, artifact, *, parents=(), max_objects=10000, manifest=None,
            parent_metadata=None, metadata_cache=None, carrier_cache=None):
    """`artifact` with a carrier of its native closure; each parent travels as its own carrier."""
    metadata_cache = {} if metadata_cache is None else metadata_cache
    carrier_cache = {} if carrier_cache is None else carrier_cache
    if artifact in carrier_cache:
        return carrier_cache[artifact]
    if manifest is None:
        manifest = verify_artifact(endpoint, artifact, metadata_cache)[1]
    if not parents:
        parents = tuple(GovernedArtifact.from_dict(item) for item in manifest["parents"])
    if parent_metadata is None:
        parent_metadata = tuple(verify_artifact(endpoint, parent, metadata_cache) for parent in parents)
    retained_parents, inherited = [], set()
    for parent, (_, parent_manifest, _) in zip(parents, parent_metadata, strict=True):
        if parent.carrier is None:
            parent = carried(endpoint, parent, max_objects=max_objects, manifest=parent_manifest,
                             metadata_cache=metadata_cache, carrier_cache=carrier_cache)
        retained_parents.append(parent.carrier)
        inherited.update((parent.reference.object_id, parent.decision_id, parent.result_id))
        inherited.update(parent_manifest["claims"])
        inherited.update(parent_manifest["action_records"])
    native = closure(endpoint, artifact, max_objects=max_objects, stop_ids=inherited)
    support = tuple(obj for identity, obj in native.items() if identity != artifact.reference.object_id)
    carrier = CarriedPublication(native[artifact.reference.object_id], tuple(retained_parents), support)
    carrier_cache[artifact] = replace(artifact, carrier=carrier)
    return carrier_cache[artifact]


def export(endpoint, artifact, *, max_objects=10000):
    """A bundle of the verified artifact's handle and its complete native closure."""
    verify_artifact(endpoint, artifact)
    native = closure(endpoint, artifact, max_objects=max_objects)
    handle = GovernedArtifact.from_dict(artifact.to_dict())
    return ArtifactBundle(handle, tuple(obj.forward() for obj in native.values()))


def receive_many(endpoint, artifacts, publications, *, max_objects, max_bytes):
    """Verify every artifact against only the transferred publications, then retain them all."""
    artifacts, publications = tuple(artifacts), tuple(publications)
    if any(not isinstance(artifact, GovernedArtifact) for artifact in artifacts):
        raise TypeError("artifact transfer requires GovernedArtifact handles")
    if (len(artifacts) > max_objects or len(publications) > max_objects
            or sum(map(len, publications)) > max_bytes):
        raise EvidenceError("artifact transfer exceeds configured limits")
    received = NativeObjects()
    for wire in publications:
        received.put(tn.GovernedObject.parse(wire))
    handles = tuple(GovernedArtifact.from_dict(artifact.to_dict()) for artifact in artifacts)
    retained = endpoint.store
    try:
        endpoint.store = received
        metadata_cache, carrier_cache = {}, {}
        for artifact in handles:
            verify_artifact(endpoint, artifact, metadata_cache)
        result = tuple(carried(endpoint, artifact, max_objects=max_objects, metadata_cache=metadata_cache,
                               carrier_cache=carrier_cache) for artifact in handles)
    finally:
        endpoint.store = retained
    for artifact in result:
        include_carrier(endpoint.store, artifact.carrier)
    return result
