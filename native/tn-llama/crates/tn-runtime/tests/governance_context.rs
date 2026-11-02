mod support;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use support::{fixture_config, prepare_and_begin, SessionHarness};
use tn_runtime::{GovernedRuntime, Phase, State};

#[test]
fn first_decision_has_verified_governance_and_no_business_values() {
    let mut harness = SessionHarness::new("Explain the protected calculation.");
    let turn = harness.session.next_model_turn().unwrap();
    assert_eq!(turn.permit.phase(), Phase::SectionSelection);
    let body: Value = serde_json::from_slice(&turn.request_json).unwrap();
    let context: Value =
        serde_json::from_str(body["messages"][1]["content"].as_str().unwrap()).unwrap();
    assert_eq!(
        context["applicable_source_governance"],
        json!(harness.governance)
    );
    assert_eq!(
        context["user_request"],
        "Explain the protected calculation."
    );
    assert!(context.get("selected_values").is_none());
    assert_eq!(body["tools"][0]["function"]["name"], "select_sections");
    assert!(!String::from_utf8_lossy(&turn.request_json).contains("get_governance"));
    prepare_and_begin(&turn, b"selection with governance", 2048, 1);
    let result = harness.section_selection_result(&["firm_data"]);
    harness
        .session
        .accept_model_action(turn.permit, result.native())
        .unwrap();
    let action = harness.session.next_model_turn().unwrap();
    assert_eq!(action.permit.phase(), Phase::GovernedAction);
    let wire = String::from_utf8_lossy(&action.request_json);
    assert!(wire.contains(harness.governance["instruction"].as_str().unwrap()));
    assert!(!wire.contains("continue_with_governance"));
}

#[test]
fn missing_governance_capability_refuses_admission_and_releases_reservation() {
    let fixture = tn_test_tools::build_real_tn_fixture().unwrap();
    let runtime = GovernedRuntime::from_config(fixture_config(&fixture)).unwrap();
    let key_path = fixture.receiver_key_dir.join("tn.agents.btn.mykit");
    let key = std::fs::read(&key_path).unwrap();
    std::fs::remove_file(&key_path).unwrap();
    let result = runtime.start_session(&fixture.row1_request_json);
    assert_eq!(result.unwrap_err().code(), "protected_group_open_failed");
    std::fs::write(key_path, key).unwrap();
    let session = runtime.start_session(&fixture.row1_request_json).unwrap();
    assert_eq!(session.state(), State::SectionSelection);
}

#[test]
fn legacy_report_model_schema_contains_only_business_output() {
    let mut harness = SessionHarness::new("Explain the firm data.");
    let selection = harness.session.next_model_turn().unwrap();
    prepare_and_begin(&selection, b"firm selection", 2048, 2);
    let result = harness.section_selection_result(&["firm_data"]);
    harness
        .session
        .accept_model_action(selection.permit, result.native())
        .unwrap();
    let action = harness.session.next_model_turn().unwrap();
    let body: Value = serde_json::from_slice(&action.request_json).unwrap();
    assert_eq!(
        body["tools"][0]["function"]["parameters"]["required"],
        json!(["report_html"])
    );
}

#[test]
fn native_admission_and_context_evidence_bind_the_actual_decision_task() {
    let mut harness = SessionHarness::new("Explain the firm data.");
    let audit_path = fixture_config(&harness._fixture).audit_path;
    let read_events = || {
        std::fs::read_to_string(&audit_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>()
    };
    let before = read_events();
    assert!(before
        .iter()
        .any(|event| event["kind"] == "governance_opened_and_verified"));
    assert!(!before
        .iter()
        .any(|event| event["kind"] == "governance_context_bound"));
    let turn = harness.session.next_model_turn().unwrap();
    let body: Value = serde_json::from_slice(&turn.request_json).unwrap();
    let context: Value =
        serde_json::from_str(body["messages"][1]["content"].as_str().unwrap()).unwrap();
    let mut hash = Sha256::new();
    hash.update(b"tn.llama.governance-context.v1\0");
    hash.update(
        tn_core::canonical::canonical_bytes(&context["applicable_source_governance"]).unwrap(),
    );
    let expected_context_digest = format!("sha256:{}", hex::encode(hash.finalize()));
    prepare_and_begin(&turn, b"verified decision prompt", 2048, 37);
    let events = read_events();
    let bound = events
        .iter()
        .find(|event| event["kind"] == "governance_context_bound")
        .unwrap();
    let facts: Value = serde_json::from_str(bound["facts_json"].as_str().unwrap()).unwrap();
    assert_eq!(bound["llama_task_id"], 37);
    assert_eq!(bound["request_digest"], harness.request_digest);
    assert_eq!(facts["context_digest"], expected_context_digest);
    assert_eq!(facts["model_request_digest"], turn.model_request_digest);
    assert_eq!(facts["source_row_hash"], harness.row_hash);
    assert_eq!(facts["phase"], 3);
    assert_eq!(facts["turn_ordinal"], 1);
    for name in ["rendered_prompt_digest", "runnable_task_digest"] {
        assert!(facts[name].as_str().unwrap().starts_with("sha256:"));
    }
    assert!(!events
        .iter()
        .any(|event| event["kind"] == "commitments_matched"));
}

#[test]
fn typed_unknown_governance_fields_reach_selection_without_loss() {
    let mut fixture = tn_test_tools::build_real_tn_fixture().unwrap();
    fixture.row1_request_json = fixture.extra_governance_field_request_json.clone();
    fixture
        .governance
        .insert("governs_sections".into(), json!(["precisely"]));
    fixture
        .governance
        .insert("governance_revision".into(), json!(2));
    let runtime = GovernedRuntime::from_config(fixture_config(&fixture)).unwrap();
    let mut harness = SessionHarness::from_fixture_and_runtime(fixture, runtime, "Explain.");
    let turn = harness.session.next_model_turn().unwrap();
    let body: Value = serde_json::from_slice(&turn.request_json).unwrap();
    let context: Value =
        serde_json::from_str(body["messages"][1]["content"].as_str().unwrap()).unwrap();
    assert_eq!(
        context["applicable_source_governance"],
        json!(harness.governance)
    );
}

#[test]
fn runtime_completed_tool_rejects_model_supplied_source_or_action() {
    for arguments in [
        json!({"source_event_id":"forged"}),
        json!({"action":"other"}),
    ] {
        let mut harness = SessionHarness::new("Explain the protected data.");
        let selection = harness.session.next_model_turn().unwrap();
        prepare_and_begin(&selection, b"selected", 2048, 1);
        let result = harness.section_selection_result(&["precisely"]);
        harness
            .session
            .accept_model_action(selection.permit, result.native())
            .unwrap();
        let turn = harness.session.next_model_turn().unwrap();
        prepare_and_begin(&turn, b"protected action", 2048, 2);
        let result =
            harness.action_result("protected-action", "log_compliance_creation", arguments);
        assert_eq!(
            harness
                .session
                .accept_model_action(turn.permit, result.native())
                .unwrap_err()
                .code(),
            "tn_tool_already_executed"
        );
        assert_eq!(harness.session.state(), State::Failed);
    }
}
