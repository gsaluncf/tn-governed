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


def sync_writes(paths) -> None:
    """Make a group of written files and their directory entries durable before their checkpoint."""
    directories = set()
    for path in paths:
        with open(path, "rb+") as stream:
            os.fsync(stream.fileno())
        directories.add(Path(path).parent)
    if not hasattr(os, "O_DIRECTORY"):
        return
    for directory in directories:
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def write_once(path: Path, content: bytes, *, sync: bool = True) -> None:
    """Atomically expose complete bytes without replacing any existing representation.

    A caller that passes ``sync=False`` owes a later ``sync_writes`` over the same paths.
    """
    if path.exists():
        if path.read_bytes() != content:
            raise ValueError(f"immutable publication representation differs: {path.name}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
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


class PublicationStore:
    """Append-only signed wire storage with an immutable, explicitly verified index."""

    def __init__(self, root: Path | str, *, read_only: bool = False,
                 group_commit: bool = False) -> None:
        self.root = Path(root)
        self.read_only = read_only
        self.group_commit = group_commit
        self._unsynced = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self) -> None:
        """The file backend has no persistent connection to close."""

    def _write(self, path: Path, content: bytes) -> None:
        write_once(path, content, sync=not self.group_commit)
        if self.group_commit:
            self._unsynced.append(path)

    def commit(self) -> None:
        """End a group of writes. Readers rely on them only after this returns."""
        sync_writes(self._unsynced)
        self._unsynced.clear()

    def publication_sizes(self) -> dict[str, int]:
        """Logical wire sizes for measurement, not a verification result."""
        return {"sha256:" + p.stem: p.stat().st_size for p in (self.root / "objects").glob("*.tn")}

    def put_record(self, snapshot, publication, *, context_id, sequence) -> None:
        validate_record_position(context_id, sequence)
        self.put(snapshot)
        self.put(publication)
        self._write(self.root / "tapes" / context_id / f"{sequence:08d}.ref",
                    publication.id.encode("ascii"))

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
        if not isinstance(object, tn.GovernedObject):
            raise TypeError("publication storage requires a native GovernedObject")
        wire = object.forward()
        digest = object_digest(object.id)
        relative = f"objects/{digest}.tn"
        self._write(self.root / relative, wire)
        index = {
            "object_id": object.id,
            "file": relative,
            "wire_sha256": hashlib.sha256(wire).hexdigest(),
        }
        self._write(
            self.root / "index" / f"{digest}.json",
            json.dumps(index, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )
        return object.id

    def get(self, object_id: str) -> bytes:
        return self.read(object_id).forward()

    def read(self, object_id: str) -> tn.GovernedObject:
        """Read current stored bytes and verify them once, without authorizing use."""
        digest = object_digest(object_id)
        index = json.loads((self.root / "index" / f"{digest}.json").read_bytes())
        relative = f"objects/{digest}.tn"
        if index.get("object_id") != object_id or index.get("file") != relative:
            raise ValueError("publication index does not name the requested identity and file")
        path = self.root / relative
        wire = path.read_bytes()
        if hashlib.sha256(wire).hexdigest() != index.get("wire_sha256"):
            raise ValueError("retained publication wire digest differs from its immutable index")
        publication = tn.GovernedObject.read(io.BytesIO(wire))
        if publication.id != object_id or publication.forward() != wire:
            raise ValueError("retained publication has the wrong native identity")
        return publication


def validate_record_position(context_id, sequence) -> None:
    if not isinstance(context_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", context_id):
        raise ValueError("invalid record context identity")
    if type(sequence) is not int or sequence < 1:
        raise ValueError("record sequence must be a positive integer")


def open_publication_store(root, *, backend=None, read_only=False) -> PublicationStore:
    """Select a storage backend explicitly, or reopen the format already on disk."""
    root = Path(root)
    has_database = (root / "publications.sqlite3").exists()
    has_files = (root / "objects").exists() or (root / "index").exists()
    if backend not in (None, "files", "sqlite") or (has_database and has_files):
        raise ValueError("unknown or ambiguous publication storage backend")
    selected = backend or ("sqlite" if has_database else "files")
    if (selected == "files" and has_database) or (selected == "sqlite" and has_files):
        raise ValueError("requested backend differs from existing publication storage")
    if selected == "sqlite":
        from .sqlite_publications import SQLitePublicationStore
        return SQLitePublicationStore(root, read_only=read_only)
    return PublicationStore(root, read_only=read_only)
