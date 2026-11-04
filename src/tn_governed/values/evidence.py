"""Context-owned evidence carried in the native TN format."""

from __future__ import annotations

import io
import json
import re
import threading
from dataclasses import dataclass
from uuid import uuid4

import tn

from tn_governed.native_objects import NativeObjects
from tn_governed.publications import sync_writes, write_once

from .references import pack_references

EVIDENCE_TYPE = "experiment.evidence"
EVIDENCE_SCHEMA = "tn.string-evidence.v1"
OBJECT_ID = re.compile(r"sha256:[0-9a-f]{64}")
KINDS = {"Decision", "Result", "Refusal", "Disclosure", "Failure", "Carry", "Claim",
         "Monitor", "Observation", "SQLRead", "ModelHandoff", "ModelResult", "ReviewRequested"}


class EvidenceError(ValueError):
    """Evidence failed verification or did not support the claimed association."""


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


@dataclass(frozen=True)
class Record:
    id: str
    writer: str
    body: dict


def check_monitor(decision, receipt):
    fields = ("context_id", "application", "purpose", "operation", "inputs", "destination")
    observed, permitted = receipt.body, decision.body
    require(receipt.writer == decision.writer and observed["kind"] == "Monitor"
            and observed["sequence"] < permitted["sequence"]
            and all(observed[key] == permitted[key] for key in fields)
            and observed["details"]["actor"] == permitted["details"]["actor"],
            "monitoring did not precede this permit")


def referenced_publications(value, lookup):
    """Resolve native identities embedded in application evidence, excluding external receipts."""
    pending, visited = [value], set()
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            pending.extend(item.values())
        elif isinstance(item, (list, tuple)):
            pending.extend(item)
        elif isinstance(item, str) and item not in visited and OBJECT_ID.fullmatch(item):
            visited.add(item)
            try:
                yield lookup(item)
            except FileNotFoundError:
                continue


def read_record(wire, *, session, policy, expected_writer=None):
    """Read TN bytes or a verified native object, then authorize evidence access.

    `policy` is the accepted evidence contract, or a tuple of accepted contracts.
    Accepting this read contract permits inspection, not endorsement of its claims.
    """
    contracts = policy if isinstance(policy, tuple) else (policy,)
    try:
        obj = wire if isinstance(wire, tn.GovernedObject) else tn.GovernedObject.read(io.BytesIO(wire))
        if obj.object_type != EVIDENCE_TYPE:
            raise EvidenceError("wrong evidence object type")
        if expected_writer is not None and obj.writer != expected_writer:
            raise EvidenceError("unexpected evidence writer")
        working = session.receive(
            obj, use=tn.UseContext("string-evidence-reader", "inspect-evidence", "read"),
            groups=["evidence"],
            decide=lambda ctx: len(ctx.policies) == 1
            and any(ctx.governance.matches_contract(contract) for contract in contracts),
        )
        body = working.get("record", group="evidence")
        required = {
            "schema", "context_id", "sequence", "previous", "kind", "call_id",
            "application", "purpose", "operation", "inputs", "destination", "details",
        }
        if not isinstance(body, dict) or set(body) != required:
            raise EvidenceError("invalid evidence record shape")
        if body["schema"] != EVIDENCE_SCHEMA or body["kind"] not in KINDS:
            raise EvidenceError("unknown evidence schema or kind")
        if type(body["sequence"]) is not int or body["sequence"] < 1:
            raise EvidenceError("invalid evidence sequence")
        for field in ("context_id", "call_id", "application", "purpose", "operation"):
            if not isinstance(body[field], str) or not body[field]:
                raise EvidenceError(f"invalid evidence {field}")
        if not isinstance(body["inputs"], (list, dict)) or not isinstance(body["details"], dict):
            raise EvidenceError("invalid evidence inputs or details")
        return Record(obj.id, obj.writer, body)
    except EvidenceError:
        raise
    except Exception as exc:
        raise EvidenceError("TN evidence verification failed") from exc


def verify_tape(wires, *, session, policy, expected_writer, expected_context, expected_head):
    """Verify a bounded record chain against an independently retained head/context/writer.

    Without a trusted head, a valid prefix cannot be distinguished from a complete record chain.
    Signatures establish attribution, not the truth of the endpoint's observations.
    """
    records = []
    previous = None
    for sequence, wire in enumerate(wires, 1):
        record = read_record(
            wire, session=session, policy=policy, expected_writer=expected_writer,
        )
        body = record.body
        if (body["context_id"] != expected_context or body["sequence"] != sequence
                or body["previous"] != previous):
            raise EvidenceError("signed record chain has a gap, reordering, or context substitution")
        records.append(record)
        previous = record.id
    if previous != expected_head:
        raise EvidenceError("signed record chain does not reach the expected head")
    return tuple(records)


class EvidenceRecorder:
    """Endpoint-owned signed records held as native objects until explicit export.

    This is an application record schema within TN, not a replacement envelope,
    signer, key service, or permit token. Each context starts a fresh record chain.
    """

    def __init__(self, session, store=None, policy=None):
        self.session = session
        self.store = NativeObjects() if store is None else store
        self.policy = session.policy(EVIDENCE_TYPE) if policy is None else policy
        self.context_id = uuid4().hex
        self._ids = []
        self._lock = threading.RLock()
        self._packed = ((), [])

    @property
    def head(self):
        return self._ids[-1] if self._ids else None

    def _packed_inputs(self, inputs):
        """The records of one call share one input tuple, so it is packed once."""
        if type(inputs) is not tuple:
            return pack_references(value.to_dict() for value in inputs)
        if self._packed[0] is not inputs:
            self._packed = inputs, pack_references(value.to_dict() for value in inputs)
        return self._packed[1]

    def append(self, kind, *, call_id, application, purpose, operation,
               inputs=(), destination=None, details=None):
        if kind not in KINDS:
            raise ValueError("unknown evidence kind")
        with self._lock:
            body = {
                "schema": EVIDENCE_SCHEMA,
                "context_id": self.context_id,
                "sequence": len(self._ids) + 1,
                "previous": self.head,
                "kind": kind,
                "call_id": call_id,
                "application": application,
                "purpose": purpose,
                "operation": operation,
                "inputs": self._packed_inputs(inputs),
                "destination": destination,
                "details": details or {},
            }
            data = self.session.create(
                {"record": body}, self.policy, object_type=EVIDENCE_TYPE, group="evidence",
            )
            snapshot = data.snapshot
            publication = self.session.release(
                data, use=tn.UseContext(application, purpose, "record-evidence"),
                to="context-recorder", object_type=EVIDENCE_TYPE,
                decide=lambda ctx: ctx.writer == self.session.did
                and len(ctx.policies) == 1 and ctx.policies[0].matches_contract(self.policy),
            )
            # Bind the signed record and its position before returning control.
            self.store.put_record(snapshot, publication, context_id=self.context_id,
                                  sequence=body["sequence"])
            if isinstance(self.store, NativeObjects):
                # Claim subjects identify what the issuer described. Inspecting the
                # signed claim requires no copy of that subject's business data.
                material = () if kind == "Claim" else (body["inputs"], body["details"])
                dependencies = referenced_publications(material, self.store.read)
                self.store.link(publication.id, (snapshot.id, *(obj.id for obj in dependencies)))
            self._ids.append(publication.id)
            return publication.id

    def ids(self):
        with self._lock:
            return tuple(self._ids)

    def records(self):
        with self._lock:
            return tuple(self.store.get(identity) for identity in self._ids)

    def read(self, identity):
        return read_record(self.store.read(identity), session=self.session, policy=self.policy)

    def export(self, directory):
        """Export exact records plus a head to retain over a separately trusted channel.

        The JSON checkpoint is an index, not a new authority or self-authenticating trust root.
        Copy the PublicationStore too when result/input publications must be inspected.
        """
        from pathlib import Path

        directory = Path(directory)
        with self._lock:
            paths, directories = [], set()
            for sequence, wire in enumerate(self.records(), 1):
                paths.append(directory / f"{sequence:08d}.tn")
                directories.update(write_once(paths[-1], wire, sync=False))
            sync_writes(paths, directories)
            checkpoint = {
                "writer": self.session.did, "context_id": self.context_id,
                "head": self.head, "count": len(self._ids),
            }
            write_once(directory / "checkpoint.json", json.dumps(checkpoint, indent=2).encode())
            return checkpoint
