"""Locally provisioned readers for retained SQL-to-report publications.

Each reader has a distinct signing key, BTN reader kit, native session, catalog,
evaluator and native object collection. Source publisher states are read without mutation.
Enrollment, publication transfer and signed catalog admission happen outside request
timing. Recipient requests still verify the carried value and its lineage and
make their own authorization decisions.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from contextlib import ExitStack, contextmanager
from pathlib import Path

import tn
import yaml
from tn._native.btn import PublisherState
from tn.signing import DeviceKey
from tn_polars.registry import EditionRegistryEntry, _index_bundle, _load_edition

from tn_governed.native_objects import NativeObjects
from tn_governed.publications import open_publication_store
from tn_governed.values.catalog import AssignedRules, ResolutionPacket, UnityGovernance
from tn_governed.values.evidence import EvidenceRecorder
from tn_governed.values.primitives import Context
from tn_governed.values.provision import POLICY
from tn_governed.values.string import ValueReference


def _source_manifest(source):
    manifest = json.loads((source / "run.json").read_text(encoding="utf-8"))
    if manifest.get("schema") != "tn.primitive-run.v1":
        raise ValueError("recipient workload requires a retained primitive run")
    if not manifest.get("outputs", {}).get("model_input"):
        raise ValueError("recipient workload requires a retained model-input value")
    summary_path = source / "case-summary.json"
    if summary_path.exists():
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        if not summary.get("completed") or not summary.get("verified"):
            raise ValueError("recipient workload source must have completed and verified")
    return manifest


def _transfer_publications(source, destination):
    with open_publication_store(source, read_only=True) as archive:
        NativeObjects.from_archive(archive).export(destination)


def _prepare(source, destinations):
    _source_manifest(source)
    manifest_bytes = (source / "run.json").read_bytes()
    catalog = source / "sessions" / "catalog"
    configuration = yaml.safe_load((catalog / "tn.yaml").read_text(encoding="utf-8"))
    key_root = Path(configuration["keystore"]["path"])
    key_root = key_root if key_root.is_absolute() else catalog / key_root
    states = {
        group: PublisherState.from_bytes((key_root / f"{group}.btn.state").read_bytes())
        for group in configuration["groups"]
    }
    kits = [{group: state.mint() for group, state in states.items()} for _ in destinations]
    for destination, reader_kits in zip(destinations, kits, strict=True):
        destination.mkdir(parents=True, exist_ok=False)
        session_root = destination / "session"
        keys = session_root / "keys"
        keys.mkdir(parents=True)
        device = DeviceKey.generate()
        (keys / "local.private").write_bytes(device.private_bytes)
        (keys / "index_master.key").write_bytes((key_root / "index_master.key").read_bytes())
        for group, kit in reader_kits.items():
            (keys / f"{group}.btn.mykit").write_bytes(kit)
            (keys / f"{group}.btn.state").write_bytes(states[group].to_bytes())
        local_configuration = json.loads(json.dumps(configuration))
        local_configuration["device"]["device_identity"] = device.did
        local_configuration["keystore"]["path"] = "keys"
        local_configuration["logs"] = {"path": "register.ndjson"}
        (session_root / "tn.yaml").write_text(
            yaml.safe_dump(local_configuration), encoding="utf-8"
        )
        shutil.copytree(catalog / ".tn", session_root / ".tn")
        _transfer_publications(source / "publications", destination / "publications")
        if (source / "editions").is_dir():
            shutil.copytree(source / "editions", destination / "editions")
        (destination / "run.json").write_bytes(manifest_bytes)
        (destination / "recipient.json").write_text(json.dumps({
            "schema": "tn.performance-recipient.v1",
            "source_directory": str(source),
            "source_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "identity": device.did,
            "reader_kits": "distinct locally minted BTN capabilities for source groups",
        }, indent=2), encoding="utf-8")
    return tuple(destinations)


def prepare_recipient(source_directory, worker_directory):
    """Create one reader with its own enrollment and received publication archive."""
    return _prepare(Path(source_directory).resolve(), [Path(worker_directory).resolve()])[0]


def prepare_recipients(source_directory, output_directory, count):
    """Allocate distinct reader leaves for one batch of enrolled endpoints."""
    if type(count) is not int or count < 1:
        raise ValueError("recipient count must be a positive integer")
    root = Path(output_directory).resolve()
    if root.exists():
        raise FileExistsError(root)
    return _prepare(Path(source_directory).resolve(), [
        root / f"endpoint-{index + 1}" for index in range(count)
    ])


def _edition_transports(root):
    transports = {}
    for index in sorted((root / "editions").glob("*/editions.json")):
        manifest = json.loads(index.read_text(encoding="utf-8"))
        if manifest.get("schema") != "tn.dataset.edition-index.v1":
            raise ValueError("retained edition index has an unknown schema")
        for item in manifest["editions"]:
            identity = item["record_id"]
            if identity in transports:
                raise ValueError("retained edition index duplicates a record identity")
            bundle = _index_bundle(index.parent.resolve(), item["bundle"])
            transports[identity] = _load_edition(
                item["dataset"], item["edition"], identity, bundle
            )
    return transports


@contextmanager
def open_recipient(worker_directory):
    """Open and admit source assignments before measuring recipient requests."""
    root = Path(worker_directory).resolve()
    checkpoint = json.loads((root / "recipient.json").read_text(encoding="utf-8"))
    if hashlib.sha256((root / "run.json").read_bytes()).hexdigest() != (
        checkpoint["source_manifest_sha256"]
    ):
        raise ValueError("recipient workload manifest differs from its source checkpoint")
    manifest = _source_manifest(root)
    request = manifest["request"]
    with ExitStack() as stack:
        session = stack.enter_context(tn.Session.from_config(str(root / "session" / "tn.yaml")))
        if session.did != checkpoint["identity"]:
            raise ValueError("recipient session identity differs from its enrollment checkpoint")
        with open_publication_store(root / "publications", read_only=True) as archive:
            store = NativeObjects.from_archive(archive)
        authority = manifest["authority"]
        admin = tn.Governance.from_markdown(
            authority, POLICY, ".tn/config/agents.md", "experiment.administration"
        )
        audit = tn.Governance.from_markdown(
            authority, POLICY, ".tn/config/agents.md", "experiment.evidence"
        )
        if (admin.fields != manifest["administration_policy"]
                or audit.fields != manifest["audit_policy"]):
            raise ValueError("source evidence contracts differ from the workload configuration")
        resolver = UnityGovernance(
            "http://unused", "retained", session=session, authority=authority,
            administration=admin, store=store,
        )
        assignment = store.read(manifest["assignment_id"])
        body = session.receive(
            assignment, use=resolver.trust.metadata_use, groups=["catalog_cfg"],
            decide=resolver.trust.metadata,
        ).get("assignment", group="catalog_cfg")
        revisions = tuple((identity, store.get(identity)) for identity in body["revisions"])
        resolver.resolve(
            body["table"], tuple(body["columns"]), actor=request["actor"],
            application=request["application"], purpose=request["purpose"],
            expected_source=manifest["source"],
            packet=ResolutionPacket(assignment.forward(), revisions, None),
        )
        rules = AssignedRules(
            resolver, actor=request["actor"], application=request["application"],
            purpose=request["purpose"], writers=[*manifest["writers"], session.did],
        )
        context = Context(
            session, EvidenceRecorder(session, store, audit), rules,
            application=request["application"], purpose=request["purpose"],
            actor=request["actor"], resolver=resolver,
        )
        transports = _edition_transports(root)
        for info in manifest["source_editions"]:
            entry = transports.get(info["record_id"]) or EditionRegistryEntry(
                info["dataset"], info["edition"], info["record_id"],
                store.get(info["record_id"]), revisions, {},
            )
            resolver.admit_edition(info, context, transport=entry)
        handle = manifest["outputs"]["model_input"]
        value = context.hydrate(
            ValueReference(**handle["reference"]), handle["decision_id"],
            handle["result_id"], kind="str",
        )
        destinations = set.intersection(*(
            set(rule["destinations"]) for rule in resolver.rules.values()
        ))
        if not destinations:
            raise ValueError("source assignments have no common disclosure destination")
        yield {
            "session": session, "store": store, "context": context, "value": value,
            "manifest": manifest, "destination": sorted(destinations)[0],
        }
