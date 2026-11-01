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
    assert original.object_id in retained
