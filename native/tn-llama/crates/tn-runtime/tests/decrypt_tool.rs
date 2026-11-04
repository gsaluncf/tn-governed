mod governed_support;
mod support;

use governed_support::*;
use serde_json::{json, Value};
use tn_runtime::{ModelTurn, Phase, Session, State};

fn wire(fixture: &Fixture) -> Value {
    serde_json::from_str(
        fixture.manifest["publications"]["calculation"]["wire"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
}

fn messages(turn: &ModelTurn) -> Vec<Value> {
    let body: Value = serde_json::from_slice(&turn.request_json).unwrap();
    body["messages"].as_array().unwrap().clone()
}

#[test]
fn decrypt_turn_shows_governance_and_hash_keys_without_values() {
    let fixture = Fixture::new();
    let request = fixture.request("calculation");
    let wire = wire(&fixture);
    let (_keys, runtime) = fixture.runtime();
    let mut session = runtime.start_session(&request).unwrap();
    let turn = session.next_model_turn().unwrap();
    assert_eq!(turn.permit.phase(), Phase::SectionSelection);
    let body: Value = serde_json::from_slice(&turn.request_json).unwrap();
    assert_eq!(body["tool_choice"], "required");
    assert_eq!(body["tools"].as_array().unwrap().len(), 1);
    assert_eq!(body["tools"][0]["function"]["name"], "decrypt_value");
    let control = control(&turn);
    assert_eq!(
        control["governance_hash"],
        wire["tn.agents"]["field_hashes"]["policy"]
    );
    let offered = wire["finance"]["field_hashes"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(field, hash)| json!({"group":"finance","field":field,"data_hash":hash}))
        .collect::<Vec<_>>();
    assert_eq!(control["encrypted_data"], json!(offered));
    assert!(!control["applicable_source_governance"]["sources"][0]["governance"]
        .as_object()
        .unwrap()
        .is_empty());
    assert!(control.get("selected_values").is_none());
    assert!(control["output_instruction"]
        .as_str()
        .unwrap()
        .contains("you can decrypt"));
    let issued = String::from_utf8(turn.request_json.clone()).unwrap();
    let opened = second_turn_values(&mut session, turn);
    assert!(!issued.contains(&opened["finance"]["calculation"].to_string()));
}

fn second_turn_values(session: &mut Session, turn: ModelTurn) -> Value {
    let arguments = decrypt_arguments(&turn, &["finance"]);
    accept(session, turn, "decrypt_value", arguments).unwrap();
    let turn = session.next_model_turn().unwrap();
    let result = messages(&turn).last().unwrap()["content"].clone();
    let result: Value = serde_json::from_str(result.as_str().unwrap()).unwrap();
    result["data"].clone()
}

#[test]
fn decrypted_values_arrive_as_the_result_of_the_models_call() {
    let fixture = Fixture::new();
    let request = fixture.request("calculation");
    let wire = wire(&fixture);
    let (_keys, runtime) = fixture.runtime();
    let mut session = runtime.start_session(&request).unwrap();
    let decrypt = session.next_model_turn().unwrap();
    let presented = decrypt_arguments(&decrypt, &["finance"]);
    accept(&mut session, decrypt, "decrypt_value", presented.clone()).unwrap();
    let turn = session.next_model_turn().unwrap();
    assert_eq!(turn.permit.phase(), Phase::GovernedAction);
    let messages = messages(&turn);
    assert_eq!(messages.len(), 4);
    let control = control(&turn);
    assert!(control.get("selected_values").is_none());
    assert!(control["applicable_source_governance"]["sources"].is_array());
    let call = &messages[2]["tool_calls"][0];
    assert_eq!(call["function"]["name"], "decrypt_value");
    let arguments: Value =
        serde_json::from_str(call["function"]["arguments"].as_str().unwrap()).unwrap();
    assert_eq!(arguments, presented);
    assert_eq!(messages[3]["role"], "tool");
    assert_eq!(messages[3]["tool_call_id"], call["id"]);
    let result: Value = serde_json::from_str(messages[3]["content"].as_str().unwrap()).unwrap();
    assert_eq!(result["data"]["finance"]["calculation"]["result"], json!(0.25));
    assert!(result["data"].get("audit").is_none());
    assert_eq!(
        result["governance_hash"],
        wire["tn.agents"]["field_hashes"]["policy"]
    );
}

#[test]
fn decrypt_returns_only_the_fields_whose_hash_keys_were_presented() {
    let fixture = Fixture::new();
    let request = fixture.request("calculation");
    let wire = wire(&fixture);
    let (_keys, runtime) = fixture.runtime();
    let mut session = runtime.start_session(&request).unwrap();
    let turn = session.next_model_turn().unwrap();
    let presented = json!({
        "governance_hash": wire["tn.agents"]["field_hashes"]["policy"],
        "data_hashes": [wire["finance"]["field_hashes"]["calculation"]],
    });
    accept(&mut session, turn, "decrypt_value", presented).unwrap();
    let turn = session.next_model_turn().unwrap();
    let result = messages(&turn).last().unwrap()["content"].clone();
    let result: Value = serde_json::from_str(result.as_str().unwrap()).unwrap();
    assert!(result["data"]["finance"]["calculation"].is_object());
    assert!(result["data"]["finance"].get("synthetic").is_none());
}

#[test]
fn decrypt_opens_only_the_groups_whose_hash_keys_were_presented() {
    let mut fixture = Fixture::new();
    fixture
        .config
        .report_contract
        .allowed_input_sections
        .insert("audit".into());
    let request = fixture.request("calculation");
    let (_keys, runtime) = fixture.runtime();
    let mut session = runtime.start_session(&request).unwrap();
    let turn = session.next_model_turn().unwrap();
    assert!(control(&turn)["encrypted_data"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["group"] == "audit"));
    let data = second_turn_values(&mut session, turn);
    assert!(data["finance"].is_object());
    assert!(data.get("audit").is_none());
}

#[test]
fn decrypt_refuses_keys_that_do_not_belong_to_this_object() {
    let fixture = Fixture::new();
    let other = fixture.manifest["publications"]["policy_earlier"]["wire"].clone();
    let other: Value = serde_json::from_str(other.as_str().unwrap()).unwrap();
    let foreign_policy = other["tn.agents"]["field_hashes"]["policy"].clone();
    assert_ne!(foreign_policy, wire(&fixture)["tn.agents"]["field_hashes"]["policy"]);
    type Change = fn(&mut Value, &Value, &Value);
    let cases: [(&str, Change); 11] = [
        ("hash key of another governance", |arguments, _, foreign| {
            arguments["governance_hash"] = foreign.clone();
        }),
        ("data hash as governance hash", |arguments, _, _| {
            arguments["governance_hash"] = arguments["data_hashes"][0].clone();
        }),
        ("governance hash as data hash", |arguments, _, _| {
            arguments["data_hashes"][0] = arguments["governance_hash"].clone();
        }),
        ("group that is not offered", |arguments, wire, _| {
            let hashes = wire["audit"]["field_hashes"].as_object().unwrap();
            arguments["data_hashes"] = json!(hashes.values().collect::<Vec<_>>());
        }),
        ("no governance hash", |arguments, _, _| {
            arguments.as_object_mut().unwrap().remove("governance_hash");
        }),
        ("no data hashes", |arguments, _, _| {
            arguments.as_object_mut().unwrap().remove("data_hashes");
        }),
        ("empty data hashes", |arguments, _, _| {
            arguments["data_hashes"] = json!([]);
        }),
        ("non-text data hash", |arguments, _, _| {
            arguments["data_hashes"] = json!([1]);
        }),
        ("repeated data hash", |arguments, _, _| {
            let hash = arguments["data_hashes"][0].clone();
            arguments["data_hashes"] = json!([hash, hash]);
        }),
        ("extra argument", |arguments, _, _| {
            arguments["group"] = json!("tn.agents");
        }),
        ("changed data hash", |arguments, _, _| {
            let mut hash = arguments["data_hashes"][0].as_str().unwrap().to_owned();
            hash.pop();
            arguments["data_hashes"][0] = json!(hash + "x");
        }),
    ];
    for (name, change) in cases {
        let fixture = Fixture::new();
        let request = fixture.request("calculation");
        let wire = wire(&fixture);
        let (_keys, runtime) = fixture.runtime();
        let mut session = runtime.start_session(&request).unwrap();
        let turn = session.next_model_turn().unwrap();
        let mut arguments = decrypt_arguments(&turn, &["finance"]);
        change(&mut arguments, &wire, &foreign_policy);
        let error = accept(&mut session, turn, "decrypt_value", arguments)
            .err()
            .unwrap_or_else(|| panic!("{name} was accepted"));
        assert_eq!(error.code(), "tn_decrypt_keys_invalid", "{name}");
        assert_eq!(session.state(), State::Failed, "{name}");
        assert!(session.next_model_turn().is_err(), "{name}");
        assert!(runtime.start_session(&request).is_ok(), "{name}");
    }
}

#[test]
fn no_other_tool_can_replace_the_decrypt_call() {
    for name in ["emit_governed_record", "select_sections", "shell"] {
        let fixture = Fixture::new();
        let request = fixture.request("calculation");
        let (_keys, runtime) = fixture.runtime();
        let mut session = runtime.start_session(&request).unwrap();
        let turn = session.next_model_turn().unwrap();
        let error = accept(&mut session, turn, name, json!({})).unwrap_err();
        assert_eq!(error.code(), "tn_action_not_allowed", "{name}");
        assert_eq!(session.state(), State::Failed, "{name}");
    }
}

#[test]
fn changing_the_governance_shown_to_the_model_stops_the_decrypt_turn() {
    let fixture = Fixture::new();
    let request = fixture.request("calculation");
    let (_keys, runtime) = fixture.runtime();
    let mut session = runtime.start_session(&request).unwrap();
    let turn = session.next_model_turn().unwrap();
    let mut body: Value = serde_json::from_slice(&turn.request_json).unwrap();
    let mut context = control(&turn);
    context["applicable_source_governance"] = json!({"sources":[]});
    body["messages"][1]["content"] = json!(context.to_string());
    let error = turn
        .permit
        .prepare(
            &serde_json::to_vec(&body).unwrap(),
            b"no governance",
            &support::literal_runnable_manifest(2048),
        )
        .unwrap_err();
    assert_eq!(error.code(), "tn_turn_binding_mismatch");
    assert_eq!(session.state(), State::Failed);
}
