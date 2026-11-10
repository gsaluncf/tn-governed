mod governed_support;
mod support;

use governed_support::*;
use serde_json::{json, Value};
use tn_core::governed::{DataObject, GovernedObject};
use tn_core::runtime::Objects;

fn branched_fixture() -> Fixture {
    let mut fixture = Fixture::new();
    let profile = fixture.config.governed_objects.as_ref().unwrap();
    let objects = Objects::open(&profile.native_reader_config_path).unwrap();
    let source = fixture.manifest["publications"]["calculation"]["wire"]
        .as_str()
        .unwrap();
    let mut metadata: Value =
        serde_json::from_slice(&std::fs::read(&profile.metadata_store_path).unwrap()).unwrap();
    metadata["publications"]
        .as_array_mut()
        .unwrap()
        .push(json!(source));
    let mut aggregate: Option<DataObject> = None;
    for index in 0..20 {
        let mut input = objects
            .receive_for(source, &profile.use_context, ["finance"], None, |_| {
                Ok(true)
            })
            .unwrap();
        input.set_field("finance", "branch", json!(index)).unwrap();
        let branch = objects
            .release_for(
                &mut input,
                "calculation.result",
                &profile.use_context,
                "internal-client",
                |_| Ok(true),
            )
            .unwrap();
        metadata["publications"]
            .as_array_mut()
            .unwrap()
            .push(json!(branch.wire()));
        let data = objects
            .receive_for(
                branch.wire(),
                &profile.use_context,
                ["finance"],
                None,
                |_| Ok(true),
            )
            .unwrap();
        if let Some(combined) = aggregate.as_mut() {
            combined.include(&data).unwrap();
        } else {
            aggregate = Some(data);
        }
    }
    let publication = objects
        .release_for(
            &mut aggregate.unwrap(),
            "calculation.result",
            &profile.use_context,
            "internal-client",
            |_| Ok(true),
        )
        .unwrap();
    std::fs::write(&profile.metadata_store_path, metadata.to_string()).unwrap();
    fixture.manifest["publications"]["calculation"]["wire"] = json!(publication.wire());
    fixture.manifest["publications"]["calculation"]["object_id"] = json!(publication.id());
    fixture
}

#[test]
fn model_references_verified_provenance_while_runtime_retains_the_full_graph() {
    let fixture = branched_fixture();
    let identity = fixture.manifest["publications"]["calculation"]["object_id"].clone();
    let source = GovernedObject::parse(
        fixture.manifest["publications"]["calculation"]["wire"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let original = Objects::open(
        &fixture
            .config
            .governed_objects
            .as_ref()
            .unwrap()
            .native_reader_config_path,
    )
    .unwrap()
    .reader()
    .unwrap()
    .governance(&source)
    .unwrap();
    let output_path = fixture.config.output_tn_config_path.clone();
    let request = fixture.request("calculation");
    let (_keys, runtime) = fixture.runtime();
    let mut session = runtime.start_session(&request).unwrap();
    let turn = report_turn(&mut session);
    let args = control(&turn);
    let reference =
        &args["applicable_source_governance"]["sources"][0]["governance"]["source_lineage"];
    assert_eq!(reference["schema"], "tn.governance-reference.v1");
    assert_eq!(reference["entry_count"], 20);
    assert_eq!(reference["source_object_id"], identity);
    assert!(reference["field_commitment"]
        .as_str()
        .unwrap()
        .starts_with("hmac-sha256:"));
    let tn_runtime::ActionOutcome::GovernedRelease(release) = accept(
        &mut session,
        turn,
        "emit_governed_record",
        json!({"report_html":"<p>25%.</p>"}),
    )
    .unwrap() else {
        panic!("expected native governed release");
    };
    let output = GovernedObject::parse(&release.output_object).unwrap();
    let retained = Objects::open(&output_path)
        .unwrap()
        .reader()
        .unwrap()
        .governance(&output)
        .unwrap();
    assert_eq!(
        retained.governance().dataset_bindings().unwrap(),
        original.governance().dataset_bindings().unwrap()
    );
    assert_eq!(
        retained.governance().policies().unwrap(),
        original.governance().policies().unwrap()
    );
    assert_eq!(original.governance().source_references().unwrap().len(), 20);
    assert_eq!(
        retained.governance().source_references().unwrap()[0].object_id(),
        source.id()
    );
}

#[test]
fn altered_provenance_reference_cannot_prepare_a_model_task() {
    for field in [
        "entry_count",
        "source_object_id",
        "field_commitment",
        "missing",
        "extra",
    ] {
        let fixture = branched_fixture();
        let request = fixture.request("calculation");
        let (_keys, runtime) = fixture.runtime();
        let mut session = runtime.start_session(&request).unwrap();
        let turn = report_turn(&mut session);
        let mut body: Value = serde_json::from_slice(&turn.request_json).unwrap();
        let mut context: Value =
            serde_json::from_str(body["messages"][1]["content"].as_str().unwrap()).unwrap();
        let reference = &mut context["applicable_source_governance"]["sources"][0]["governance"]
            ["source_lineage"];
        if field == "missing" {
            reference.as_object_mut().unwrap().remove("entry_count");
        } else {
            reference[field] = json!("substituted");
        }
        body["messages"][1]["content"] = json!(context.to_string());
        assert_eq!(
            turn.permit
                .prepare(
                    &serde_json::to_vec(&body).unwrap(),
                    b"altered provenance",
                    &support::literal_runnable_manifest(2048)
                )
                .unwrap_err()
                .code(),
            "tn_turn_binding_mismatch"
        );
        assert_eq!(session.state(), tn_runtime::State::Failed);
    }
}
