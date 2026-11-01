"""Transactional version indexes over immutable governed artifacts."""

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from .endpoints import GovernedArtifact


class HistoryConflict(ValueError):
    """The requested predecessor is not the retained head for this key."""


class ValueHistory:
    """A local ordered index; artifact signatures carry the portable history.

    BEGIN IMMEDIATE serializes competing head transitions across connections.
    A crash may leave an unindexed immutable publication, never a partial head.
    The index is checked against signed predecessor fields whenever it is read.
    """

    def __init__(self, path, endpoint):
        self.path, self.endpoint = Path(path), endpoint
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS versions ("
                "name TEXT NOT NULL, sequence INTEGER NOT NULL, artifact TEXT NOT NULL, "
                "PRIMARY KEY(name,sequence))"
            )

    @contextmanager
    def _connection(self):
        connection = sqlite3.connect(self.path, timeout=30)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _versions(self, connection, name):
        rows = connection.execute(
            "SELECT sequence,artifact FROM versions WHERE name=? ORDER BY sequence", (name,)
        ).fetchall()
        versions = []
        previous_state = None
        for expected, (sequence, encoded) in enumerate(rows, 1):
            artifact = GovernedArtifact.from_dict(json.loads(encoded))
            manifest = self.endpoint.metadata(artifact)
            history = manifest["parameters"].get("history")
            prior = None if not versions else versions[-1].reference.object_id
            if (
                sequence != expected
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
            previous_state = manifest["state"]
            versions.append(artifact)
        return tuple(versions)

    def versions(self, name):
        with self._connection() as connection:
            return self._versions(connection, name)

    def head(self, name):
        versions = self.versions(name)
        return versions[-1] if versions else None

    def _change(self, name, expected, operation, inputs, compute, reason=None):
        if not isinstance(name, str) or not name:
            raise ValueError("history keys must be nonempty strings")
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            versions = self._versions(connection, name)
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
            connection.execute(
                "INSERT INTO versions VALUES (?,?,?)",
                (name, len(versions) + 1, json.dumps(output.to_dict(), sort_keys=True)),
            )
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
