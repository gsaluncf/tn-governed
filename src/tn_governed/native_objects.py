"""Native publications carried by values and explicitly serialized at boundaries."""

from __future__ import annotations

import threading
from dataclasses import dataclass

import tn

from .publications import PublicationStore, object_digest, validate_record_position


@dataclass(frozen=True, slots=True, eq=False)
class CarriedPublication:
    """A native publication with shared, immutable supporting object references."""

    object: tn.GovernedObject
    parents: tuple[CarriedPublication, ...] = ()
    support: tuple[tn.GovernedObject, ...] = ()

    def __post_init__(self):
        if not isinstance(self.object, tn.GovernedObject):
            raise TypeError("carried publication requires a native GovernedObject")
        if not isinstance(self.parents, tuple) or any(
            not isinstance(parent, CarriedPublication) for parent in self.parents
        ):
            raise TypeError("carried parents must be native publication carriers")
        if not isinstance(self.support, tuple) or any(
            not isinstance(obj, tn.GovernedObject) for obj in self.support
        ):
            raise TypeError("carried support must contain native GovernedObject instances")

    def objects(self):
        """Visit each carried native identity once, without copying its wire bytes."""
        pending, carriers, objects = [self], set(), set()
        while pending:
            carrier = pending.pop()
            if id(carrier) in carriers:
                continue
            carriers.add(id(carrier))
            for obj in (carrier.object, *carrier.support):
                if obj.id not in objects:
                    objects.add(obj.id)
                    yield obj
            pending.extend(reversed(carrier.parents))

    def resolve(self, identity):
        object_digest(identity)
        for obj in self.objects():
            if obj.id == identity:
                return obj
        raise FileNotFoundError(f"publication is not carried: {identity}")


def include_carrier(store, carrier):
    """Retain every publication a carrier holds, in a native collection or a publication store."""
    if isinstance(store, NativeObjects):
        store.include(carrier)
    else:
        for obj in carrier.objects():
            store.put(obj)


class NativeObjects:
    """Endpoint-owned native references; no files, serialization, or database I/O.

    Values keep their own carriers. This collection gives an endpoint access to
    objects while evaluating them and retains its local operation records.
    """

    def __init__(self):
        self._objects = {}
        self._dependencies = {}
        self._records = {}
        self._included = {}
        self._lock = threading.RLock()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        """Native references follow ordinary Python object lifetime."""

    def put(self, publication):
        if not isinstance(publication, tn.GovernedObject):
            raise TypeError("native object collection requires a GovernedObject")
        identity = publication.id
        object_digest(identity)
        with self._lock:
            self._objects.setdefault(identity, publication)
        return identity

    def read(self, identity):
        object_digest(identity)
        with self._lock:
            try:
                return self._objects[identity]
            except KeyError:
                raise FileNotFoundError(f"publication is not available: {identity}") from None

    def get(self, identity):
        """Serialize a publication for an explicit native transport consumer."""
        return self.read(identity).forward()

    def link(self, identity, *dependency_ids):
        """Record known transport dependencies without granting authority or use."""
        object_digest(identity)
        if len(dependency_ids) == 1 and not isinstance(dependency_ids[0], str):
            dependency_ids = tuple(dependency_ids[0])
        for dependency in dependency_ids:
            object_digest(dependency)
        with self._lock:
            self._dependencies.setdefault(identity, set()).update(dependency_ids)

    def put_record(self, snapshot, publication, *, context_id, sequence):
        validate_record_position(context_id, sequence)
        if not isinstance(snapshot, tn.GovernedObject) or not isinstance(
            publication, tn.GovernedObject
        ):
            raise TypeError("signed records require native snapshot and publication objects")
        with self._lock:
            records = self._records.setdefault(context_id, {})
            before, after = snapshot.id, publication.id
            if sequence in records and records[sequence] != after:
                raise ValueError("immutable record reference differs")
            self.put(snapshot)
            self.put(publication)
            records[sequence] = after
            self.link(after, before)

    def record_ids(self, context_id):
        validate_record_position(context_id, 1)
        with self._lock:
            records = self._records.get(context_id, {})
            if set(records) != set(range(1, len(records) + 1)):
                raise ValueError("record sequence has a gap")
            return tuple(records[index] for index in range(1, len(records) + 1))

    def record_contexts(self):
        with self._lock:
            return tuple(sorted(self._records))

    def include(self, carrier):
        if not isinstance(carrier, CarriedPublication):
            raise TypeError("native handoff requires a carried publication")
        with self._lock:
            pending = [carrier]
            while pending:
                current = pending.pop()
                if id(current) in self._included:
                    continue
                self._included[id(current)] = current
                self.put(current.object)
                for obj in current.support:
                    self.put(obj)
                pending.extend(current.parents)

    def carry(self, root_id, *, parents=(), extra_ids=()):
        parents = tuple(parents)
        with self._lock:
            for parent in parents:
                self.include(parent)
            root = self.read(root_id)
            inherited = {parent.object.id for parent in parents}
            inherited.update(obj.id for parent in parents for obj in parent.support)
            pending = [root_id, *extra_ids]
            visited, support = set(), []
            while pending:
                identity = pending.pop()
                if identity in visited:
                    continue
                visited.add(identity)
                if identity in inherited:
                    continue
                obj = self.read(identity)
                if identity != root_id:
                    support.append(obj)
                pending.extend(self._dependencies.get(identity, ()))
            return CarriedPublication(root, parents, tuple(support))

    def publication_sizes(self):
        """Serialize retained objects when explicitly collecting wire-size metrics."""
        with self._lock:
            return {identity: len(obj.forward()) for identity, obj in self._objects.items()}

    def export(self, directory):
        """Persist native publications once at an explicit archival boundary."""
        archive = PublicationStore(directory, group_commit=True)
        with self._lock:
            for obj in self._objects.values():
                archive.put(obj)
            for context_id, records in self._records.items():
                for sequence, identity in sorted(records.items()):
                    archive.put_reference(context_id, sequence, identity)
            archive.commit()
        return archive

    @classmethod
    def from_archive(cls, archive):
        objects = cls()
        for identity in archive.publication_sizes():
            objects.put(archive.read(identity))
        for context in archive.record_contexts():
            objects._records[context] = dict(enumerate(archive.record_ids(context), 1))
        return objects
