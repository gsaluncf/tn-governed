mod governed_support;
mod support;

use governed_support::SessionHarness;
use serde_json::Value;
use sha2::{Digest, Sha256};
use support::{fixture_config, prepare_and_begin};

#[test]
fn native_admission_and_context_evidence_bind_the_actual_decision_task() {
    let mut harness = SessionHarness::new("Explain the maximum drawdown.");
    let audit_path = fixture_config(&harness.keys).audit_path;
    let read_events = || {
        std::fs::read_to_string(&audit_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>()
    };
    let before = read_events();
    let reserved = before
        .iter()
        .find(|event| event["kind"] == "standalone_object_reserved")
        .unwrap()
        .clone();
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
    assert_eq!(bound["request_digest"], reserved["request_digest"]);
    assert_eq!(facts["context_digest"], expected_context_digest);
    assert_eq!(facts["model_request_digest"], turn.model_request_digest);
    assert_eq!(facts["source_object_id"], harness.object_id);
    assert_eq!(facts["phase"], 3);
    assert_eq!(facts["turn_ordinal"], 1);
    for name in ["rendered_prompt_digest", "runnable_task_digest"] {
        assert!(facts[name].as_str().unwrap().starts_with("sha256:"));
    }
    assert!(!events
        .iter()
        .any(|event| event["kind"] == "commitments_matched"));
}
