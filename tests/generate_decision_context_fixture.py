"""Generate synthetic native claim fixtures from the signed primitive workflow.

Run with the repository Python environment from the repository root. Enrollment
uses disposable test identities; no installed reader or publisher keys are read.
"""

import base64
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace

import pytest
import tn
import yaml

from test_report_review_completion import report_workflow
from tn_llama_client.protocol import build_model_request
from tn_governed.values.string import ValueReference


def boundary_fixture(workflow, profile, with_claim=True):
    session = workflow.context.session
    use = workflow.endpoint.use
    policy = workflow.context._metadata(workflow.value)[0].policies[0]
    data = session.create({"value": "ACME"}, policy,
                          object_type="experiment.primitive", group="values")
    snapshots = [data.snapshot.forward().decode("utf-8")]
    manifest = {"schema": "tn.primitive-bindings.v1", "bindings": {
        "value": {"claims": [], "parents": []}}}
    data.set(None, {"manifest": manifest}, group="evidence")
    original = session.release(data, use=use, to="fixture", decide=lambda _: True)
    subject = ValueReference(original.id, "value", "values")
    claim_id = workflow.context.recorder.append("Claim", call_id="edition-attestation",
        application="analytics", purpose="internal", operation="attest", inputs=[subject],
        details={"statement": "The selected edition retains this original subject."}) if with_claim else None
    data = session.receive(original, use=use, groups=["values", "evidence"], decide=lambda _: True)
    manifest["bindings"]["value"] = {"claims": [claim_id] if with_claim else [], "parents": [subject.to_dict()]}
    data.set(None, {"manifest": manifest}, group="evidence")
    attested = session.release(data, use=use, to="fixture", decide=lambda _: True)
    permission = profile["contracts"][0]
    with tn.Session.from_config(str(workflow.root / "input-sessions/catalog/tn.yaml")) as authority:
        draft = tn.DatasetEditionDraft("claim-origin", "selected", attested, ["values", "evidence"],
            [tn.ContractBinding(permission["revision_id"], permission["scope"])], [use], "fixture", [])
        edition_object = authority.seal(draft.into_draft(authority.policy("experiment.administration")))
        admitted = authority.governance(edition_object).accept(use=use, groups=["dataset_edition"], decide=lambda _: True)
        opened = authority.open(admitted, ["dataset_edition"])
        edition = tn.DatasetEdition.from_opened(opened)
        catalog = tn.DatasetCatalog()
        catalog.admit(edition, workflow.context.policy_dag, lambda _: True)
        selection = catalog.select("claim-origin", "selected", edition.id, use)
        data = session.receive(attested, use=use, groups=["values", "evidence"],
                               selection=selection, decide=lambda _: True)
        manifest["bindings"]["value"]["parents"] = [ValueReference(attested.id, "value", "values").to_dict()]
        data.set(None, {"manifest": manifest}, group="evidence")
        output = session.release(data, use=use, to="fixture", decide=lambda _: True)
    return {"source": output.forward().decode("utf-8"), "subject_id": original.id,
        "claim_record": workflow.context.recorder.store.get(claim_id).decode("utf-8") if with_claim else None,
        "edition": edition_object.forward().decode("utf-8"),
        "publications": [*snapshots, original.forward().decode("utf-8"), attested.forward().decode("utf-8")]}


def generate_carried():
    """Generate the current wire sample using the same producer and real endpoint config as the test."""
    with tempfile.TemporaryDirectory() as directory, pytest.MonkeyPatch.context() as monkeypatch:
        from dataclasses import replace
        from tn_governed.values.catalog import AssignedRules
        evaluate = AssignedRules.__call__
        def require_monitor(rules, request):
            result = evaluate(rules, request)
            return replace(result, obligations=("monitor",)) if result.permit and request.operation == "upper" else result
        monkeypatch.setattr(AssignedRules, "__call__", require_monitor)
        fixture = report_workflow.__wrapped__(Path(directory), monkeypatch, SimpleNamespace(param="native"))
        workflow = next(fixture)
        try:
            profile = json.loads(workflow.endpoint.runtime_config.read_bytes())["governed_objects"]
            config = Path(profile["native_reader_config_path"])
            metadata = json.loads(Path(profile["metadata_store_path"]).read_bytes())
            _, _, claims = workflow.context._metadata(workflow.value)
            profile.update(native_reader_config_path="input/tn.yaml", metadata_store_path="metadata.json")
            result = {
                "profile": profile, "metadata": metadata, "reader_config": yaml.safe_load(config.read_text()),
                "keys": {p.name: base64.b64encode(p.read_bytes()).decode("ascii")
                         for p in (config.parent / "keys").iterdir()},
                "request": json.loads(build_model_request(workflow.source, "Describe the company.",
                    workflow.endpoint.use, destination=workflow.endpoint.requirements["report_destination"])),
                "expected_claim": {"record_id": claims[0].id, "issuer": claims[0].issuer,
                    "statement": claims[0].statement,
                    "original_subjects": [subject.to_dict() for subject in claims[0].subjects]},
            }
            data, binding, _ = workflow.context._metadata(workflow.value)
            field = {"group": "values", "claims": binding["claims"], "actions": binding["actions"]}
            generic = data.policy_output("finance.calculation", {
                "values": {"share": 0.25}, "evidence": {"manifest": {
                    "schema": "tn.governed-fields.v1", "bindings": {"share": field}}},
            })
            generic = workflow.context.session.release(generic, use=workflow.endpoint.use, to="internal-model",
                object_type="finance.calculation", decide=lambda _: True)
            result["generic"] = generic.forward().decode("utf-8")
            direct_id, edition = next(iter(workflow.context.editions.items()))
            result["direct"] = workflow.context.store_object(direct_id).wire
            result["direct_edition_id"] = edition.id
            target = Path("native/tn-llama/crates/tn-runtime/tests/fixtures/carried-decision.json")
            target.write_text(json.dumps(result, separators=(",", ":")) + "\n", encoding="utf-8")
        finally:
            fixture.close()


def generate():
    with tempfile.TemporaryDirectory() as directory, pytest.MonkeyPatch.context() as monkeypatch:
        # The workflow fixture is parametrized; tn-llama's claim fixture is the native case.
        fixture = report_workflow.__wrapped__(Path(directory), monkeypatch, SimpleNamespace(param="native"))
        workflow = next(fixture)
        try:
            config = json.loads(workflow.endpoint.runtime_config.read_bytes())
            profile = config["governed_objects"]
            native_config = Path(profile["native_reader_config_path"])
            metadata = json.loads(Path(profile["metadata_store_path"]).read_bytes())
            profile["native_reader_config_path"] = "input/tn.yaml"
            profile["metadata_store_path"] = "metadata.json"
            _, _, claims = workflow.context._metadata(workflow.value)
            recorder = workflow.context.recorder
            detached = recorder.append("Claim", call_id="detached-attestation", application="analytics",
                purpose="internal", operation="attest", inputs=claims[0].subjects,
                details={"statement": "Identification requires additional verification."})
            variants = {}
            for name in ("detached-claim", "dropped-claim", "unknown-parent-field", "missing-manifest", "missing-binding", "missing-parents"):
                data = workflow.context.session.receive(workflow.source,
                    use=workflow.endpoint.use, groups=["values", "evidence"], decide=lambda _: True)
                manifest = data.get("manifest", group="evidence")
                binding = manifest["bindings"][workflow.value.reference.field]
                binding["parents"] = [workflow.value.reference.to_dict()]
                if name == "detached-claim":
                    binding["claims"].append(detached)
                elif name == "dropped-claim":
                    binding["claims"] = []
                elif name == "unknown-parent-field":
                    binding["parents"][0]["field"] = "absent"
                elif name == "missing-binding":
                    manifest["bindings"] = {}
                elif name == "missing-parents":
                    binding["claims"] = []
                    binding["parents"] = []
                data.set(None, {} if name == "missing-manifest" else {"manifest": manifest}, group="evidence")
                publication = workflow.context.session.release(data, use=workflow.endpoint.use,
                    to=workflow.endpoint.requirements["report_destination"],
                    object_type=workflow.source.object_type, decide=lambda _: True)
                variants[name] = publication.forward().decode("utf-8")
            with workflow.context:
                disputed = workflow.value.attest("Identification requires additional verification.", workflow.context)
            _, _, disputed_claims = workflow.context._metadata(disputed)
            disputed_source = workflow.context.store_object(disputed.reference.object_id)
            variants["distinct-claims"] = disputed_source.forward().decode("utf-8")
            result = {
                "profile": profile,
                "reader_config": yaml.safe_load(native_config.read_text()),
                "keys": {path.name: base64.b64encode(path.read_bytes()).decode("ascii")
                         for path in sorted((native_config.parent / "keys").iterdir())},
                "metadata": metadata,
                "request": json.loads(build_model_request(workflow.source, "Describe the company.",
                    workflow.endpoint.use, destination=workflow.endpoint.requirements["report_destination"])),
                "expected_claim": {"record_id": claims[0].id, "issuer": claims[0].issuer,
                    "statement": claims[0].statement,
                    "original_subjects": [subject.to_dict() for subject in claims[0].subjects]},
                "variants": variants,
                "extra_claim_records": [recorder.store.get(identity).decode("utf-8") for identity in
                    [detached, *[claim.id for claim in disputed_claims if claim.id != claims[0].id]]],
                "catalog_boundary": boundary_fixture(workflow, profile),
                "claim_free_boundary": boundary_fixture(workflow, profile, with_claim=False),
            }
            target = Path("native/tn-llama/crates/tn-runtime/tests/fixtures/decision-context.json")
            target.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        finally:
            fixture.close()


if __name__ == "__main__":
    generate_carried()
