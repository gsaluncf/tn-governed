mod governed_support;
mod support;
use governed_support::{report_turn, Fixture};
use serde_json::{json, Value};
use tn_runtime::{Phase, State};

#[test]
fn decision_context_retains_nested_records_without_generated_bookkeeping() {
    let fixture = Fixture::new();
    let request = fixture.request("calculation");
    let (_keys, runtime) = fixture.runtime();
    let mut session = runtime.start_session(&request).unwrap();
    let turn = report_turn(&mut session);
    assert_eq!(turn.permit.phase(), Phase::GovernedAction);
    let body: Value = serde_json::from_slice(&turn.request_json).unwrap();
    let context: Value =
        serde_json::from_str(body["messages"][1]["content"].as_str().unwrap()).unwrap();
    let governance = &context["applicable_source_governance"]["sources"][0]["governance"];
    assert!(governance["dataset_bindings"].is_array());
    assert!(governance["source_lineage"].is_array());
    assert_eq!(governance["release_context"]["operation"], "calculate");
    let parameters = &body["tools"][0]["function"]["parameters"];
    assert_eq!(parameters["required"], json!(["report_html"]));
    assert!(parameters["properties"].get("governance").is_none());
}

#[test]
fn nested_policy_substitution_fails_the_model_request_binding() {
    let fixture = Fixture::new();
    let request = fixture.request("calculation");
    let (_keys, runtime) = fixture.runtime();
    let mut session = runtime.start_session(&request).unwrap();
    let turn = report_turn(&mut session);
    let mut body: Value = serde_json::from_slice(&turn.request_json).unwrap();
    let mut context: Value =
        serde_json::from_str(body["messages"][1]["content"].as_str().unwrap()).unwrap();
    context["applicable_source_governance"]["sources"][0]["governance"]["release_context"]
        ["operation"] = json!("substituted");
    body["messages"][1]["content"] = json!(context.to_string());
    assert_eq!(
        turn.permit
            .prepare(
                &serde_json::to_vec(&body).unwrap(),
                b"altered governance",
                &support::literal_runnable_manifest(2048)
            )
            .unwrap_err()
            .code(),
        "tn_turn_binding_mismatch"
    );
    assert_eq!(session.state(), State::Failed);
}
