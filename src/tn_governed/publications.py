"""Retain exact canonical TN publications; transport never creates a new version."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import tempfile
from functools import lru_cache
from pathlib import Path

import tn


_IDENTITY = re.compile(r"sha256:[0-9a-f]{64}")
_IDENTITY_ERROR = "publication identity requires sha256 and 64 lowercase hexadecimal digits"


def object_digest(object_id: str) -> str:
    """Validate an identity before using its digest as a local path component."""
    if not isinstance(object_id, str):
        raise ValueError(_IDENTITY_ERROR)
    return _string_digest(object_id)


@lru_cache(maxsize=65536)
def _string_digest(object_id: str) -> str:
    if not _IDENTITY.fullmatch(object_id):
        raise ValueError(_IDENTITY_ERROR)
    return object_id[7:]


def sync_directories(directories) -> None:
    """Make directory entries durable where the platform can synchronize a directory."""
    if not hasattr(os, "O_DIRECTORY"):
        return
    for directory in directories:
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def sync_writes(paths, directories=()) -> None:
    """Make a group of written files and their directory entries durable before their checkpoint.

    `directories` names further directories whose entries changed, such as the parents
    of directories the writes created.
    """
    changed = set(directories)
    for path in paths:
        with open(path, "rb+") as stream:
            os.fsync(stream.fileno())
        changed.add(Path(path).parent)
    sync_directories(changed)


def _make_parents(path: Path) -> list[Path]:
    """Create `path`'s directory; return every directory whose entries changed."""
    missing, directory = [], path.parent
    while not directory.exists():
        missing.append(directory)
        directory = directory.parent
    for created in reversed(missing):
        created.mkdir(exist_ok=True)
    return [created.parent for created in reversed(missing)] + [path.parent]


def write_once(path: Path, content: bytes, *, sync: bool = True) -> list[Path]:
    """Atomically expose complete bytes without replacing any existing representation.

    A caller that passes ``sync=False`` owes a later ``sync_writes`` over the same path
    and the directories this returns.
    """
    if path.exists():
        if path.read_bytes() != content:
            raise ValueError(f"immutable publication representation differs: {path.name}")
        return []
    changed = _make_parents(path)
    descriptor, temporary = tempfile.mkstemp(prefix=".publication-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            if sync:
                os.fsync(output.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.read_bytes() != content:
                raise ValueError(
                    f"immutable publication representation differs: {path.name}"
                ) from None
    finally:
        Path(temporary).unlink(missing_ok=True)
    if not sync:
        return changed
    sync_directories(changed)
    return []


def encode_publication(publication) -> tuple[str, bytes, str]:
    """A native publication's identity, exact wire bytes, and their digest, for storage."""
    if not isinstance(publication, tn.GovernedObject):
        raise TypeError("publication storage requires a native GovernedObject")
    wire = publication.forward()
    object_digest(publication.id)
    return publication.id, wire, hashlib.sha256(wire).hexdigest()


def verified_publication(object_id: str, wire: bytes, wire_sha256) -> tn.GovernedObject:
    """Verify retained bytes against their recorded digest and native identity, not their use."""
    if hashlib.sha256(wire).hexdigest() != wire_sha256:
        raise ValueError("retained publication wire digest differs from its immutable index")
    publication = tn.GovernedObject.read(io.BytesIO(wire))
    if publication.id != object_id or publication.forward() != wire:
        raise ValueError("retained publication has the wrong native identity")
    return publication


def stored_backend(root: Path) -> str | None:
    """The storage format already at `root`: "files", "sqlite", or None; both is refused."""
    has_database = (root / "publications.sqlite3").exists()
    has_files = (root / "objects").exists() or (root / "index").exists()
    if has_database and has_files:
        raise ValueError("unknown or ambiguous publication storage backend")
    return "sqlite" if has_database else "files" if has_files else None


class Storage:
    """What both storage backends share: closing, serialized reads, and group commits."""

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self) -> None:
        """A backend with no persistent connection has nothing to close."""

    def commit(self) -> None:
        """End a group of writes. Readers rely on them only after this returns."""

    def get(self, object_id: str) -> bytes:
        return self.read(object_id).forward()


class PublicationStore(Storage):
    """Append-only signed wire storage in files, with an immutable, explicitly verified index."""

    def __init__(self, root: Path | str, *, read_only: bool = False,
                 group_commit: bool = False) -> None:
        self.root = Path(root)
        if stored_backend(self.root) == "sqlite":
            raise ValueError("requested backend differs from existing publication storage")
        self.read_only = read_only
        self.group_commit = group_commit
        self._unsynced, self._unsynced_directories = [], set()

    def _write(self, path: Path, content: bytes) -> None:
        changed = write_once(path, content, sync=not self.group_commit)
        if self.group_commit:
            self._unsynced.append(path)
            self._unsynced_directories.update(changed)

    def commit(self) -> None:
        sync_writes(self._unsynced, self._unsynced_directories)
        self._unsynced.clear()
        self._unsynced_directories.clear()

    def publication_sizes(self) -> dict[str, int]:
        """Logical wire sizes for measurement, not a verification result."""
        return {"sha256:" + p.stem: p.stat().st_size for p in (self.root / "objects").glob("*.tn")}

    def put_record(self, snapshot, publication, *, context_id, sequence) -> None:
        validate_record_position(context_id, sequence)
        self.put(snapshot)
        self.put(publication)
        self.put_reference(context_id, sequence, publication.id)

    def put_reference(self, context_id, sequence, object_id) -> None:
        """Retain one record-chain position; an existing position never changes."""
        validate_record_position(context_id, sequence)
        object_digest(object_id)
        if self.read_only:
            raise PermissionError("publication store is read-only")
        self._write(self.root / "tapes" / context_id / f"{sequence:08d}.ref", object_id.encode("ascii"))

    def record_ids(self, context_id) -> tuple[str, ...]:
        validate_record_position(context_id, 1)
        files = sorted((self.root / "tapes" / context_id).glob("*.ref"))
        identities = []
        for sequence, path in enumerate(files, 1):
            if path.name != f"{sequence:08d}.ref":
                raise ValueError("record sequence has a gap")
            identity = path.read_text(encoding="ascii")
            object_digest(identity)
            identities.append(identity)
        return tuple(identities)

    def record_contexts(self) -> tuple[str, ...]:
        """Enumerate archived record chains without reading publication contents."""
        tapes = self.root / "tapes"
        if not tapes.is_dir():
            return ()
        contexts = tuple(sorted(path.name for path in tapes.iterdir() if path.is_dir()))
        for context in contexts:
            validate_record_position(context, 1)
        return contexts

    def put(self, object: tn.GovernedObject) -> str:
        if self.read_only:
            raise PermissionError("publication store is read-only")
        identity, wire, wire_sha256 = encode_publication(object)
        relative = f"objects/{identity[7:]}.tn"
        self._write(self.root / relative, wire)
        index = {"object_id": identity, "file": relative, "wire_sha256": wire_sha256}
        self._write(
            self.root / "index" / f"{identity[7:]}.json",
            json.dumps(index, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )
        return identity

    def read(self, object_id: str) -> tn.GovernedObject:
        """Read current stored bytes and verify them once, without authorizing use."""
        digest = object_digest(object_id)
        index = json.loads((self.root / "index" / f"{digest}.json").read_bytes())
        relative = f"objects/{digest}.tn"
        if index.get("object_id") != object_id or index.get("file") != relative:
            raise ValueError("publication index does not name the requested identity and file")
        return verified_publication(object_id, (self.root / relative).read_bytes(), index.get("wire_sha256"))


def validate_record_position(context_id, sequence) -> None:
    if not isinstance(context_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", context_id):
        raise ValueError("invalid record context identity")
    if type(sequence) is not int or sequence < 1:
        raise ValueError("record sequence must be a positive integer")


def open_publication_store(root, *, backend=None, read_only=False) -> Storage:
    """Select a storage backend explicitly, or reopen the format already on disk."""
    root = Path(root)
    if backend not in (None, "files", "sqlite"):
        raise ValueError("unknown or ambiguous publication storage backend")
    existing = stored_backend(root)
    selected = backend or existing or "files"
    if existing is not None and existing != selected:
        raise ValueError("requested backend differs from existing publication storage")
    if selected == "sqlite":
        from .sqlite_publications import SQLitePublicationStore
        return SQLitePublicationStore(root, read_only=read_only)
    return PublicationStore(root, read_only=read_only)
