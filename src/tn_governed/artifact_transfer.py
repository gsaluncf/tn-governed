"""Bounded native closures of artifacts: carriers between endpoints, export, and admitted transfer."""

from __future__ import annotations

from dataclasses import replace

import tn

from .artifact_types import ArtifactBundle, GovernedArtifact
from .artifact_verification import verify_artifact
from .native_objects import CarriedPublication, NativeObjects, include_carrier
from .values.evidence import OBJECT_ID, EvidenceError


def _objects(endpoint, artifact, manifest, max_objects):
    ids = {artifact.reference.object_id, *manifest["claims"], *manifest["action_records"]}
    if artifact.result_id:
        ids.add(artifact.result_id)
    for identity in manifest["action_records"]:
        details = endpoint._record(identity).body["details"]
        if "action_progress" in details:
            ids.update(details["action_progress"])
        else:
            ids.update(step["evidence"] for step in details["discharged"] if OBJECT_ID.fullmatch(step["evidence"]))
    if len(ids) > max_objects:
        raise EvidenceError("artifact transfer exceeds the configured object limit")
    return {identity: endpoint.store.read(identity) for identity in ids}


def carried(endpoint, artifact, *, max_objects=10000, manifest=None):
    if manifest is None:
        manifest = verify_artifact(endpoint, artifact)[1]
    objects = _objects(endpoint, artifact, manifest, max_objects)
    publication = objects.pop(artifact.reference.object_id)
    return replace(artifact, carrier=CarriedPublication(publication, support=tuple(objects.values())))


def export(endpoint, artifact, *, max_objects=10000):
    """A bundle of the verified artifact's handle and its complete native closure."""
    manifest = verify_artifact(endpoint, artifact)[1]
    native = _objects(endpoint, artifact, manifest, max_objects)
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
        result = tuple(carried(endpoint, artifact, max_objects=max_objects) for artifact in handles)
    finally:
        endpoint.store = retained
    for artifact in result:
        include_carrier(endpoint.store, artifact.carrier)
    return result
