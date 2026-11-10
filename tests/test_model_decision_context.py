"""Model preparation retains the signed records required for native claim admission."""

import json

import tn

from test_report_review_completion import report_workflow as report_workflow


def test_preparation_retains_exact_claim_and_authorizes_its_evidence_contract(report_workflow):
    workflow = report_workflow
    metadata = json.loads((workflow.root / "model/native-metadata.json").read_bytes())
    _, _, claims = workflow.context._metadata(workflow.value)
    assert len(claims) == 1
    assert metadata.get("claim_records") == [
        workflow.context.recorder.store.get(claims[0].id).decode("utf-8")
    ]
    config = json.loads(workflow.endpoint.runtime_config.read_bytes())
    grants = config["governed_objects"].get("evidence_contracts")
    assert grants == [{
        "governed_by": workflow.context.recorder.policy.governed_by,
        "fields": workflow.context.recorder.policy.fields,
        "allowed_uses": [config["governed_objects"]["use_context"]],
    }]
    original = claims[0].subjects[0]
    retained = {tn.GovernedObject.parse(wire).id for wire in metadata["publications"]}
    assert config["governed_objects"]["carried_policy"] is True
    assert not retained
    assert original.object_id != workflow.value.reference.object_id

def test_singleton_sql_input_uses_the_edition_signed_for_its_hash(report_workflow):
    from pathlib import Path
    from tn_governed.values.model import prepare_native_model

    workflow = report_workflow
    old = json.loads(workflow.endpoint.runtime_config.read_bytes())
    profile = old["governed_objects"]
    root = workflow.root
    source = workflow.source_handle
    obj = workflow.context.store_object(source.reference.object_id)
    assert not workflow.input_session.governance(obj).governance.dataset_bindings
    edition = workflow.context.editions[obj.id]
    with tn.Session.from_config(old["output_tn_config_path"]) as publisher:
        path, reader, _ = prepare_native_model(
            source, context=workflow.context, input_session=workflow.input_session, output_session=publisher,
            recipient_session=workflow.reader.session, input_config=profile["native_reader_config_path"],
            output_config=old["output_tn_config_path"], directory=root / "source-model",
            model=root / "model.gguf", binary=root / "server",
        )
    profile = json.loads(path.read_bytes())["governed_objects"]
    assert profile["source_edition_id"] == edition.id
    assert reader.source_binding.edition_record_id == edition.id
    metadata = json.loads(Path(profile["metadata_store_path"]).read_bytes())
    assert [tn.GovernedObject.parse(w).id for w in metadata["dataset_editions"]] == [edition.id]
    assert not metadata["publications"]
    selection = workflow.context.catalog.select(edition.dataset, edition.edition, edition.id, workflow.endpoint.use)
    release = workflow.construct_release(source=obj, selection=selection)
    assert "ACME" in reader.open(release).get("report_html", group="default")
