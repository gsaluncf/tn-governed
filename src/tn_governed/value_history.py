"""In-memory governed value evolution with explicit native history transfer."""

from __future__ import annotations

import json
import os
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

from .endpoints import Endpoint, GovernedArtifact


class HistoryConflict(ValueError):
    """A version disagrees with its signed predecessor or the expected local head."""


@dataclass(frozen=True)
class HistorySnapshot:
    """A transport index and the exact native publications that authenticate it."""

    versions: tuple[tuple[str, tuple[GovernedArtifact, ...]], ...]
    publications: tuple[bytes, ...]

    def to_bytes(self):
        return json.dumps(
            {
                "schema": "tn.value-history.v1",
                "versions": [
                    {"key": key, "artifacts": [artifact.to_dict() for artifact in artifacts]}
                    for key, artifacts in self.versions
                ],
                "publications": [wire.decode("utf-8") for wire in self.publications],
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def parse(cls, wire, *, max_bytes=64 * 1024 * 1024):
        """Decode a transport index; receiving endpoints verify its native evidence."""
        if not isinstance(wire, bytes) or len(wire) > max_bytes:
            raise ValueError("history snapshot requires bounded bytes")
        value = json.loads(wire)
        if (
            not isinstance(value, dict)
            or set(value) != {"schema", "versions", "publications"}
            or value["schema"] != "tn.value-history.v1"
            or not isinstance(value["versions"], list)
            or not isinstance(value["publications"], list)
            or any(not isinstance(item, str) for item in value["publications"])
        ):
            raise ValueError("invalid history snapshot")
        versions = []
        for entry in value["versions"]:
            if (
                not isinstance(entry, dict)
                or set(entry) != {"key", "artifacts"}
                or not isinstance(entry["key"], str)
                or not isinstance(entry["artifacts"], list)
            ):
                raise ValueError("invalid history version index")
            versions.append(
                (
                    entry["key"],
                    tuple(GovernedArtifact.from_dict(item) for item in entry["artifacts"]),
                )
            )
        return cls(tuple(versions), tuple(item.encode("utf-8") for item in value["publications"]))


def _write_snapshot(path, content):
    path = Path(path)
    if path.is_file():
        with path.open("rb") as stream:
            if stream.read(16) == b"SQLite format 3\x00":
                raise ValueError("history export cannot overwrite a SQLite archive")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".history-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


class ValueHistory:
    """Ordered native artifact references owned by this application object.

    ``ValueHistory(endpoint)`` holds versions in memory. The two-argument form
    ``ValueHistory(path, endpoint)`` configures a destination used only by an
    explicit ``export()``; construction and transitions neither read nor write
    that path. Receiving a snapshot is an explicit endpoint admission boundary.

    A lock serializes competing transitions on the same history instance.
    Transferred histories have independent heads and local endpoint decisions.
    """

    def __init__(self, path=None, endpoint=None):
        self.path = None if endpoint is None or path is None else Path(path)
        self.endpoint = path if endpoint is None else endpoint
        if not isinstance(self.endpoint, Endpoint):
            raise TypeError("value history requires a governed endpoint")
        self._versions = {}
        self._states = {}
        self._lock = threading.RLock()

    @staticmethod
    def _key(name):
        if not isinstance(name, str) or not name:
            raise ValueError("history keys must be nonempty strings")

    def _check_transition(self, name, sequence, artifact, previous, previous_state):
        manifest = self.endpoint.metadata(artifact)
        history = manifest["parameters"].get("history")
        prior = None if previous is None else previous.reference.object_id
        if (
            not isinstance(history, dict)
            or type(history.get("sequence")) is not int
            or history != {"key": name, "sequence": sequence, "previous": prior}
            or manifest["operation"] not in {"insert", "rederive", "delete", "restore"}
            or (
                prior is not None
                and prior
                not in {parent["reference"]["object_id"] for parent in manifest["parents"]}
            )
        ):
            raise HistoryConflict("version index differs from signed predecessor evidence")
        transition = (previous_state, manifest["operation"], manifest["state"])
        if transition not in {
            (None, "insert", "active"),
            ("active", "rederive", "active"),
            ("active", "delete", "deleted"),
            ("deleted", "restore", "active"),
        }:
            raise HistoryConflict("version index contains an invalid signed state transition")
        return manifest["state"]

    def versions(self, name):
        self._key(name)
        with self._lock:
            return self._versions.get(name, ())

    def head(self, name):
        versions = self.versions(name)
        return versions[-1] if versions else None

    def _change(self, name, expected, operation, inputs, compute, reason=None):
        self._key(name)
        with self._lock:
            versions = self._versions.get(name, ())
            head = versions[-1] if versions else None
            if head != expected:
                raise HistoryConflict("value head changed before this operation")
            if operation != "insert" and head is None:
                raise HistoryConflict("a successor requires an existing version")
            inputs = tuple(inputs)
            if head is not None and head not in inputs:
                inputs = (head, *inputs)
            parameters = {
                "history": {
                    "key": name,
                    "sequence": len(versions) + 1,
                    "previous": None if head is None else head.reference.object_id,
                }
            }
            if reason is not None:
                parameters["reason"] = reason
            if operation == "delete":
                output = self.endpoint.retire(head, parameters=parameters)
            elif operation == "restore":
                output = self.endpoint.restore(head, inputs[-1], parameters=parameters)
            else:
                output = self.endpoint.execute(operation, inputs, compute, parameters=parameters)
            state = self._check_transition(
                name, len(versions) + 1, output, head, self._states.get(name)
            )
            # A compute callback can reenter this object while the RLock is held.
            if self._versions.get(name, ()) != versions:
                raise HistoryConflict("value head changed during this operation")
            self._versions[name] = (*versions, output)
            self._states[name] = state
            return output

    def insert(self, name, artifact):
        return self._change(name, None, "insert", (artifact,), lambda values: values[0])

    def rederive(self, name, *, expected, inputs, compute):
        inputs = tuple(inputs)
        includes_previous = expected in inputs
        return self._change(
            name,
            expected,
            "rederive",
            inputs,
            compute if includes_previous else lambda values: compute(values[1:]),
        )

    def delete(self, name, *, expected, reason):
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("deletion requires a recorded reason")
        return self._change(name, expected, "delete", (expected,), None, reason)

    def restore(self, name, *, expected, artifact):
        return self._change(name, expected, "restore", (artifact,), None)

    def export(self, path=None):
        """Serialize exact native evidence, optionally saving an atomic snapshot."""
        with self._lock:
            publications = {}
            versions = []
            for name, artifacts in self._versions.items():
                bundle = self.endpoint.export(artifacts[-1])
                for wire in bundle.publications:
                    publications.setdefault(wire, None)
                versions.append(
                    (name, tuple(GovernedArtifact.from_dict(item.to_dict()) for item in artifacts))
                )
            snapshot = HistorySnapshot(tuple(versions), tuple(publications))
        destination = self.path if path is None else Path(path)
        if destination is not None:
            _write_snapshot(destination, snapshot.to_bytes())
        return snapshot

    @classmethod
    def receive(cls, snapshot, endpoint):
        """Admit native publications and check signed transitions before installing heads."""
        if not isinstance(snapshot, HistorySnapshot):
            raise TypeError("history transfer requires a HistorySnapshot")
        result = cls(endpoint)
        names = set()
        for name, artifacts in snapshot.versions:
            cls._key(name)
            if name in names or not isinstance(artifacts, tuple) or not artifacts:
                raise HistoryConflict("history keys must have one nonempty version sequence")
            names.add(name)
        handles = tuple(
            GovernedArtifact.from_dict(artifact.to_dict())
            for _, artifacts in snapshot.versions
            for artifact in artifacts
        )
        admitted = (
            endpoint.receive_many(handles, publications=snapshot.publications) if handles else ()
        )
        versions, states = {}, {}
        offset = 0
        for name, artifacts in snapshot.versions:
            accepted = admitted[offset : offset + len(artifacts)]
            offset += len(artifacts)
            state = None
            previous = None
            for sequence, arrived in enumerate(accepted, 1):
                state = result._check_transition(
                    name, sequence, arrived, previous, state
                )
                previous = arrived
            versions[name] = accepted
            states[name] = state
        result._versions, result._states = versions, states
        return result
