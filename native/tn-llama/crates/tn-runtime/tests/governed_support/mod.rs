#![allow(dead_code)]
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use std::fs;
use tn_runtime::{ActionOutcome, GovernedRuntime, ModelTurn, RuntimeConfig, Session, TnLlamaError};

pub struct Fixture {
    pub legacy: tn_test_tools::RealTnFixture,
    pub manifest: Value,
    pub config: RuntimeConfig,
    pub runtime_json: Vec<u8>,
}
impl Fixture {
    pub fn require_compliance(&mut self) {
        self.config.report_contract.section_rules.insert(
            "finance".into(),
            tn_runtime::SectionRule {
                propagate_source_governance: true,
                required_attribution: None,
                required_tool: Some("log_compliance_creation".into()),
            },
        );
        let mut config: Value = serde_json::from_slice(&self.runtime_json).unwrap();
        config["report_contract"]["section_rules"] = json!({"finance":{
            "propagate_source_governance":true, "required_attribution":null,
            "required_tool":"log_compliance_creation"
        }});
        self.runtime_json = serde_json::to_vec(&config).unwrap();
    }
    pub fn new() -> Self {
        let legacy = tn_test_tools::build_real_tn_fixture().unwrap();
        let manifest: Value =
            serde_json::from_str(include_str!("../fixtures/governed/manifest.json")).unwrap();
        let input = legacy.temp.path().join("native-input");
        let keys = input.join("keys");
        fs::create_dir_all(&keys).unwrap();
        fs::write(
            keys.join("local.private"),
            hex::decode(manifest["private_seed_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        fs::write(
            keys.join("index_master.key"),
            hex::decode(manifest["index_master_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        for (name, group) in manifest["groups"].as_object().unwrap() {
            let kit = STANDARD
                .decode(group["reader_kit_base64"].as_str().unwrap())
                .unwrap();
            fs::write(keys.join(format!("{name}.btn.mykit")), &kit).unwrap();
            fs::write(
                keys.join(format!("{name}.btn.state")),
                STANDARD
                    .decode(group["publisher_state_base64"].as_str().unwrap())
                    .unwrap(),
            )
            .unwrap();
        }
        let native = json!({"ceremony":{"id":"cer_governed_m1_test_fixture","cipher":"btn","mode":"local"},
            "keystore":{"path":"keys"},"device":{"device_identity":manifest["writer"]},
            "groups":manifest["groups"].as_object().unwrap().keys().map(|name| (name.clone(),json!({"cipher":"btn","policy":"private","index_epoch":0}))).collect::<serde_json::Map<_,_>>()});
        fs::write(input.join("tn.yaml"), native.to_string()).unwrap();
        let publications = &manifest["publications"];
        let metadata = json!({
            "policy_revisions":[publications["policy_earlier"]["wire"],publications["policy_later"]["wire"]],
            "dataset_editions":[publications["edition_earlier"]["wire"],publications["edition_later"]["wire"]],
            "publications":[publications["source_earlier"]["wire"],publications["source_later"]["wire"],publications["joined"]["wire"]]
        });
        fs::write(input.join("metadata.json"), metadata.to_string()).unwrap();
        let mut config = super::support::fixture_config(&legacy);
        config.expected_event_type = "calculation.result".into();
        config.allowed_input_groups = ["finance".into(), "audit".into()].into();
        config.report_contract.allowed_input_sections = ["finance".into()].into();
        config.report_contract.section_rules.clear();
        config.report_contract.output_event_type = "portfolio.report".into();
        config.report_contract.operation = "generate_report".into();
        config.input_index_key_path = keys.join("index_master.key");
        config.ceremony_id = "cer_governed_m1_test_fixture".into();
        let profile = json!({
            "native_reader_config_path":input.join("tn.yaml"), "metadata_store_path":input.join("metadata.json"),
            "use_context":manifest["uses"]["model"], "destinations":["internal-client"],
            "trusted_writers":[manifest["writer"]], "authority_writers":[manifest["writer"]],
            "contracts":(["policy_earlier","policy_later"].iter().map(|name| json!({
                "revision_id":publications[*name]["object_id"],"scope":"finance.wealth_path","allowed_uses":[manifest["uses"]["model"]]
            })).collect::<Vec<_>>())
        });
        config.governed_objects = Some(serde_json::from_value(profile.clone()).unwrap());
        let mut runtime_json: Value = serde_json::from_slice(
            &fs::read(legacy.temp.path().join("runtime-config.json")).unwrap(),
        )
        .unwrap();
        runtime_json["governed_objects"] = profile;
        runtime_json["expected_event_type"] = json!(config.expected_event_type);
        runtime_json["allowed_input_groups"] = json!(config.allowed_input_groups);
        runtime_json["input_index_key_path"] = json!(config.input_index_key_path);
        runtime_json["ceremony_id"] = json!(config.ceremony_id);
        runtime_json["report_contract"]["allowed_input_sections"] = json!(["finance"]);
        runtime_json["report_contract"]["section_rules"] = json!({});
        runtime_json["report_contract"]["output_event_type"] =
            json!(config.report_contract.output_event_type);
        runtime_json["report_contract"]["operation"] = json!(config.report_contract.operation);
        Self {
            legacy,
            manifest,
            config,
            runtime_json: serde_json::to_vec(&runtime_json).unwrap(),
        }
    }
    /// The input session's kit for `group`, from the native reader's own keystore.
    pub fn input_kit(&self, group: &str) -> std::path::PathBuf {
        let reader = &self
            .config
            .governed_objects
            .as_ref()
            .unwrap()
            .native_reader_config_path;
        reader
            .parent()
            .unwrap()
            .join("keys")
            .join(format!("{group}.btn.mykit"))
    }
    /// The calculation publication requested with `content` as the user's message.
    pub fn request_with(&self, content: &str) -> Vec<u8> {
        let mut request: Value = serde_json::from_slice(&self.request("calculation")).unwrap();
        request["messages"][0]["content"] = json!(content);
        serde_json::to_vec(&request).unwrap()
    }
    pub fn request(&self, publication: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({"protocol":"tn.llama.request.v2", "tn_object":self.manifest["publications"][publication]["wire"],
            "use":self.manifest["uses"]["model"],"destination":"internal-client", "messages":[{"role":"user","content":"Explain the maximum drawdown."}],"stream":false})).unwrap()
    }
    pub fn runtime(self) -> (tn_test_tools::RealTnFixture, GovernedRuntime) {
        (
            self.legacy,
            GovernedRuntime::from_config(self.config).unwrap(),
        )
    }
}

pub fn accept(
    session: &mut Session,
    turn: ModelTurn,
    name: &str,
    arguments: Value,
) -> Result<ActionOutcome, TnLlamaError> {
    let body: Value = serde_json::from_slice(&turn.request_json).unwrap();
    super::support::prepare_and_begin(
        &turn,
        b"native-fixture-rendered",
        body["max_tokens"].as_u64().unwrap() as u32,
        11,
    );
    let result = super::support::OwnedToolResult {
        id: format!("native-{name}").into_bytes(),
        name: name.as_bytes().to_vec(),
        arguments: serde_json::to_vec(&arguments).unwrap(),
        raw: b"native fixture tool result".to_vec(),
        content: vec![],
        call_count: 1,
        truncated: false,
        stop_limit: false,
    };
    session.accept_model_action(turn.permit, result.native())
}
pub fn control(turn: &ModelTurn) -> Value {
    let body: Value = serde_json::from_slice(&turn.request_json).unwrap();
    serde_json::from_str(body["messages"][1]["content"].as_str().unwrap()).unwrap()
}
/// The hash keys the decrypt turn shows for the named groups.
pub fn decrypt_arguments(turn: &ModelTurn, groups: &[&str]) -> Value {
    let control = control(turn);
    let data_hashes = control["encrypted_data"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| groups.contains(&entry["group"].as_str().unwrap()))
        .map(|entry| entry["data_hash"].clone())
        .collect::<Vec<_>>();
    json!({"governance_hash":control["governance_hash"], "data_hashes":data_hashes})
}
pub fn select(session: &mut Session, groups: &[&str]) -> Result<(), TnLlamaError> {
    let turn = session.next_model_turn()?;
    let arguments = decrypt_arguments(&turn, groups);
    accept(session, turn, "decrypt_value", arguments)?;
    Ok(())
}
/// The first turn after the model decrypts the finance group.
pub fn report_turn(session: &mut Session) -> ModelTurn {
    select(session, &["finance"]).unwrap();
    session.next_model_turn().unwrap()
}

/// A native session over the fixture's calculation publication, for session and runtime tests.
pub struct SessionHarness {
    pub keys: tn_test_tools::RealTnFixture,
    pub runtime: GovernedRuntime,
    pub session: Session,
    pub raw_request: Vec<u8>,
    pub object_id: String,
}

impl SessionHarness {
    pub fn new(user_content: &str) -> Self {
        let fixture = Fixture::new();
        let raw_request = fixture.request_with(user_content);
        let (keys, runtime) = fixture.runtime();
        Self::with_runtime(keys, runtime, raw_request)
    }

    pub fn with_runtime(
        keys: tn_test_tools::RealTnFixture,
        runtime: GovernedRuntime,
        raw_request: Vec<u8>,
    ) -> Self {
        let session = runtime.start_session(&raw_request).unwrap();
        let request: Value = serde_json::from_slice(&raw_request).unwrap();
        let object_id =
            tn_core::governed::GovernedObject::parse(request["tn_object"].as_str().unwrap())
                .unwrap()
                .id()
                .to_owned();
        Self {
            keys,
            runtime,
            session,
            raw_request,
            object_id,
        }
    }

    /// The model's decrypt call for `groups`, built from the hash keys the turn shows.
    pub fn decrypt_result(
        &self,
        turn: &ModelTurn,
        groups: &[&str],
    ) -> super::support::OwnedToolResult {
        super::support::OwnedToolResult {
            id: b"call-decrypt-3".to_vec(),
            name: b"decrypt_value".to_vec(),
            arguments: super::support::canonical_json(&decrypt_arguments(turn, groups)),
            raw: br#"<tool_call>{"name":"decrypt_value"}</tool_call>"#.to_vec(),
            content: Vec::new(),
            call_count: 1,
            truncated: false,
            stop_limit: false,
        }
    }

    pub fn action_result(
        &self,
        id: &str,
        name: &str,
        arguments: Value,
    ) -> super::support::OwnedToolResult {
        super::support::OwnedToolResult {
            id: id.as_bytes().to_vec(),
            name: name.as_bytes().to_vec(),
            arguments: super::support::canonical_json(&arguments),
            raw: format!(r#"<tool_call>{{"name":"{name}"}}</tool_call>"#).into_bytes(),
            content: Vec::new(),
            call_count: 1,
            truncated: false,
            stop_limit: false,
        }
    }
}
