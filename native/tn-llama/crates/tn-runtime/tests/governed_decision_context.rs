mod governed_support;
mod support;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use tn_runtime::GovernedRuntime;

fn fixture() -> (governed_support::Fixture, Value) {
    fixture_from(include_str!("fixtures/decision-context.json"))
}

fn fixture_from(wire: &str) -> (governed_support::Fixture, Value) {
    let mut fixture = governed_support::Fixture::new();
    let mut claim: Value = serde_json::from_str(wire).unwrap();
    let root = fixture.legacy.temp.path().join("claims");
    let keys = root.join("input/keys");
    std::fs::create_dir_all(&keys).unwrap();
    for (name, encoded) in claim["keys"].as_object().unwrap() {
        std::fs::write(
            keys.join(name),
            STANDARD.decode(encoded.as_str().unwrap()).unwrap(),
        )
        .unwrap();
    }
    std::fs::write(
        root.join("input/tn.yaml"),
        claim["reader_config"].to_string(),
    )
    .unwrap();
    std::fs::write(root.join("metadata.json"), claim["metadata"].to_string()).unwrap();
    claim["profile"]["native_reader_config_path"] = json!(root.join("input/tn.yaml"));
    claim["profile"]["metadata_store_path"] = json!(root.join("metadata.json"));
    fixture.config.governed_objects =
        Some(serde_json::from_value(claim["profile"].clone()).unwrap());
    fixture.config.expected_event_type = "experiment.primitive".into();
    fixture.config.allowed_input_groups = ["values".into(), "evidence".into()].into();
    fixture.config.report_contract.allowed_input_sections = ["values".into()].into();
    fixture.config.input_index_key_path = keys.join("index_master.key");
    fixture.config.ceremony_id = claim["reader_config"]["ceremony"]["id"]
        .as_str()
        .unwrap()
        .into();
    (fixture, claim)
}

fn first_context(fixture: governed_support::Fixture, claim: &Value) -> Value {
    let request = serde_json::to_vec(&claim["request"]).unwrap();
    let (_keys, runtime) = fixture.runtime();
    let mut session = runtime.start_session(&request).unwrap();
    let turn = session.next_model_turn().unwrap();
    let body: Value = serde_json::from_slice(&turn.request_json).unwrap();
    let control: Value =
        serde_json::from_str(body["messages"][1]["content"].as_str().unwrap()).unwrap();
    control["applicable_source_governance"].clone()
}

#[test]
fn signed_claim_retains_issuer_statement_and_original_subject_in_first_decision() {
    let (fixture, claim) = fixture();
    let objects = tn_core::runtime::Objects::open(
        &fixture
            .config
            .governed_objects
            .as_ref()
            .unwrap()
            .native_reader_config_path,
    )
    .unwrap();
    let record = tn_core::governed::GovernedObject::parse(
        claim["metadata"]["claim_records"][0].as_str().unwrap(),
    )
    .unwrap();
    let evidence = objects.reader().unwrap().governance(&record).unwrap();
    let context = first_context(fixture, &claim);
    assert_eq!(context["schema"], "tn.llama.decision-context.v1");
    assert_eq!(context["claims"].as_array().unwrap().len(), 1);
    for field in ["record_id", "issuer", "statement", "original_subjects"] {
        assert_eq!(context["claims"][0][field], claim["expected_claim"][field]);
    }
    assert_eq!(
        context["claims"][0]["governed_by"],
        evidence.governance().governed_by()
    );
    assert_eq!(
        context["claims"][0]["governance"],
        json!(evidence.governance().fields())
    );
    assert_eq!(
        context["sources"][0]["object_id"],
        serde_json::from_str::<Value>(claim["request"]["tn_object"].as_str().unwrap()).unwrap()
            ["row_hash"]
    );
    assert_ne!(
        context["claims"][0]["original_subjects"][0]["object_id"],
        context["sources"][0]["object_id"]
    );
}

#[test]
fn referenced_claim_requires_signed_record_and_evidence_grant() {
    for failure in [
        "missing-record",
        "modified-signature",
        "missing-grant",
        "wrong-use",
    ] {
        let (mut fixture, mut claim) = fixture();
        match failure {
            "missing-record" => claim["metadata"]["claim_records"] = json!([]),
            "modified-signature" => {
                let mut wire: Value =
                    serde_json::from_str(claim["metadata"]["claim_records"][0].as_str().unwrap())
                        .unwrap();
                wire["signature"] = json!("invalid");
                claim["metadata"]["claim_records"][0] = json!(wire.to_string());
            }
            "missing-grant" => {
                claim["profile"]["evidence_contracts"] = json!([]);
            }
            "wrong-use" => {
                claim["profile"]["evidence_contracts"][0]["allowed_uses"][0]["purpose"] =
                    json!("unrelated");
            }
            _ => unreachable!(),
        }
        fixture.config.governed_objects =
            Some(serde_json::from_value(claim["profile"].clone()).unwrap());
        std::fs::write(
            &fixture
                .config
                .governed_objects
                .as_ref()
                .unwrap()
                .metadata_store_path,
            claim["metadata"].to_string(),
        )
        .unwrap();
        let runtime = GovernedRuntime::from_config(fixture.config).unwrap();
        let result = runtime.start_session(&serde_json::to_vec(&claim["request"]).unwrap());
        let error = result
            .err()
            .unwrap_or_else(|| panic!("{failure} reached decision issuance"));
        let expected = match failure {
            "missing-record" => "tn_claim_record_missing",
            "modified-signature" => "tn_claim_record_invalid",
            _ => "tn_claim_access_denied",
        };
        assert_eq!(error.code(), expected, "{failure}");
    }
}

#[test]
fn signed_manifest_must_preserve_claims_and_their_original_association() {
    for variant in [
        "detached-claim",
        "dropped-claim",
        "unknown-parent-field",
        "missing-manifest",
        "missing-binding",
        "missing-parents",
    ] {
        let (fixture, mut claim) = fixture();
        claim["request"]["tn_object"] = claim["variants"][variant].clone();
        let extra = claim["extra_claim_records"].as_array().unwrap().clone();
        claim["metadata"]["claim_records"]
            .as_array_mut()
            .unwrap()
            .extend(extra);
        std::fs::write(
            &fixture
                .config
                .governed_objects
                .as_ref()
                .unwrap()
                .metadata_store_path,
            claim["metadata"].to_string(),
        )
        .unwrap();
        let (_keys, runtime) = fixture.runtime();
        let error = runtime
            .start_session(&serde_json::to_vec(&claim["request"]).unwrap())
            .err()
            .unwrap_or_else(|| panic!("{variant} reached decision issuance"));
        let expected = match variant {
            "unknown-parent-field" => "tn_claim_subject_invalid",
            "missing-manifest" | "missing-binding" => "tn_claim_manifest_invalid",
            _ => "tn_claim_association_invalid",
        };
        assert_eq!(error.code(), expected, "{variant}");
    }
}

#[test]
fn distinct_signed_claims_retain_each_statement_and_subject() {
    let (fixture, mut claim) = fixture();
    claim["request"]["tn_object"] = claim["variants"]["distinct-claims"].clone();
    let extra = claim["extra_claim_records"].as_array().unwrap().clone();
    claim["metadata"]["claim_records"]
        .as_array_mut()
        .unwrap()
        .extend(extra);
    std::fs::write(
        &fixture
            .config
            .governed_objects
            .as_ref()
            .unwrap()
            .metadata_store_path,
        claim["metadata"].to_string(),
    )
    .unwrap();
    let context = first_context(fixture, &claim);
    let claims = context["claims"].as_array().unwrap();
    assert_eq!(claims.len(), 2);
    assert!(claims
        .iter()
        .any(|item| item["statement"] == "Suitable for internal company identification."));
    assert!(claims
        .iter()
        .any(|item| item["statement"] == "Identification requires additional verification."));
    assert_ne!(claims[0]["record_id"], claims[1]["record_id"]);
    assert_ne!(
        claims[0]["original_subjects"],
        claims[1]["original_subjects"]
    );
}

#[test]
fn claim_subject_before_selected_catalog_origin_requires_its_exact_ancestry() {
    for name in ["catalog_boundary", "claim_free_boundary"] {
        for retain_subject in [true, false] {
            let (fixture, mut claim) = fixture();
            let boundary = claim[name].clone();
            claim["request"]["tn_object"] = boundary["source"].clone();
            if !boundary["claim_record"].is_null() {
                claim["metadata"]["claim_records"]
                    .as_array_mut()
                    .unwrap()
                    .push(boundary["claim_record"].clone());
            }
            claim["metadata"]["dataset_editions"]
                .as_array_mut()
                .unwrap()
                .push(boundary["edition"].clone());
            for publication in boundary["publications"].as_array().unwrap() {
                let object: Value = serde_json::from_str(publication.as_str().unwrap()).unwrap();
                if retain_subject || object["row_hash"] != boundary["subject_id"] {
                    claim["metadata"]["publications"]
                        .as_array_mut()
                        .unwrap()
                        .push(publication.clone());
                }
            }
            std::fs::write(
                &fixture
                    .config
                    .governed_objects
                    .as_ref()
                    .unwrap()
                    .metadata_store_path,
                claim["metadata"].to_string(),
            )
            .unwrap();
            if retain_subject {
                let context = first_context(fixture, &claim);
                assert_eq!(
                    context["claims"].as_array().unwrap().len(),
                    usize::from(name == "catalog_boundary")
                );
                if name == "catalog_boundary" {
                    assert_eq!(
                        context["claims"][0]["original_subjects"][0]["object_id"],
                        boundary["subject_id"]
                    );
                }
            } else {
                let (_keys, runtime) = fixture.runtime();
                let error = runtime
                    .start_session(&serde_json::to_vec(&claim["request"]).unwrap())
                    .err()
                    .expect("catalog selection must not erase original claim subject evidence");
                assert_eq!(error.code(), "tn_claim_subject_missing");
            }
        }
    }
}

#[test]
fn current_signed_value_admits_claim_without_calculation_inputs() {
    let (fixture, claim) = fixture_from(include_str!("fixtures/carried-decision.json"));
    assert_eq!(claim["metadata"]["publications"], json!([]));
    assert!(!claim["metadata"]["action_records"]
        .as_array()
        .unwrap()
        .is_empty());
    let context = first_context(fixture, &claim);
    assert_eq!(
        context["claims"][0]["original_subjects"],
        claim["expected_claim"]["original_subjects"]
    );
    assert_eq!(
        context["claims"][0]["statement"],
        claim["expected_claim"]["statement"]
    );
    assert!(context["sources"][0]["governance"]
        .get("source_lineage")
        .is_none());
    assert!(context["sources"][0]["governance"]
        .get("dataset_bindings")
        .is_none());
}

#[test]
fn missing_claim_action_or_evidence_permission_refuses_current_value() {
    for target in ["claim_records", "action_records", "evidence_contracts"] {
        let (mut fixture, mut claim) = fixture_from(include_str!("fixtures/carried-decision.json"));
        if target == "evidence_contracts" {
            fixture
                .config
                .governed_objects
                .as_mut()
                .unwrap()
                .evidence_contracts
                .clear();
        } else {
            claim["metadata"][target] = json!([]);
            std::fs::write(
                &fixture
                    .config
                    .governed_objects
                    .as_ref()
                    .unwrap()
                    .metadata_store_path,
                claim["metadata"].to_string(),
            )
            .unwrap();
        }
        let runtime = GovernedRuntime::from_config(fixture.config).unwrap();
        let error = runtime
            .start_session(&serde_json::to_vec(&claim["request"]).unwrap())
            .err()
            .unwrap();
        assert_eq!(
            error.code(),
            match target {
                "claim_records" => "tn_claim_record_missing",
                "action_records" => "tn_action_record_missing",
                _ => "tn_claim_access_denied",
            }
        );
    }
}

#[test]
fn structured_value_carries_field_claim_and_action_receipts() {
    let (mut fixture, mut claim) = fixture_from(include_str!("fixtures/carried-decision.json"));
    fixture.config.expected_event_type = "finance.calculation".into();
    claim["request"]["tn_object"] = claim["generic"].clone();
    let context = first_context(fixture, &claim);
    assert_eq!(
        context["claims"][0]["record_id"],
        claim["expected_claim"]["record_id"]
    );
    assert_eq!(
        context["claims"][0]["original_subjects"],
        claim["expected_claim"]["original_subjects"]
    );
}

#[test]
fn singleton_source_requires_its_exact_signed_edition() {
    for select_edition in [true, false] {
        let (mut fixture, mut claim) = fixture_from(include_str!("fixtures/carried-decision.json"));
        claim["request"]["tn_object"] = claim["direct"].clone();
        fixture
            .config
            .governed_objects
            .as_mut()
            .unwrap()
            .source_edition_id =
            select_edition.then(|| claim["direct_edition_id"].as_str().unwrap().to_string());
        if select_edition {
            let context = first_context(fixture, &claim);
            assert_eq!(context["claims"], json!([]));
            assert!(!context["sources"][0]["governance"]["instruction"].is_null());
        } else {
            let runtime = GovernedRuntime::from_config(fixture.config).unwrap();
            let error = runtime
                .start_session(&serde_json::to_vec(&claim["request"]).unwrap())
                .err()
                .unwrap();
            assert_eq!(error.code(), "tn_governed_use_denied");
        }
    }
}
