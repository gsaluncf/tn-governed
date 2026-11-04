use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::contract::OutputPolicy;
use crate::error::{AdmissionStage, TnLlamaError};
use crate::model_phase::Phase;
use crate::output_tn::SourceLineage;

pub const MODEL_REQUEST_DIGEST_DOMAIN: &[u8] = b"tn.llama.model-request.v1\0";
pub const RENDERED_PROMPT_DIGEST_DOMAIN: &[u8] = b"tn.llama.rendered-prompt.v1\0";
pub const RUNNABLE_TASK_DIGEST_DOMAIN: &[u8] = b"tn.llama.runnable-task.v1\0";
pub const RUNNABLE_TASK_SCHEMA: &str = "tn.llama.runnable-task.v1";

const HASH_KEY_PATTERN: &str = "^hmac-sha256:v1:[0-9a-f]{64}$";
pub(crate) const SYSTEM_CONTENT: &str = "This is a server-governed action interaction. Call exactly one available tool and return no prose. Generate only the requested business arguments and output fields. Governance in the current request applies to every decision; source identities, cryptographic evidence, and authorization are bound by the runtime. The server validates, executes, emits, and releases every action.";

pub(crate) fn governance_presentation(
    plaintext: &BTreeMap<String, Value>,
    commitments: &BTreeMap<String, String>,
    source_object_id: &str,
) -> Result<BTreeMap<String, Value>, TnLlamaError> {
    // Only typed provenance collections are summarized. Policy text, attached
    // contracts, claims, and extension fields retain their authenticated values.
    let mut presentation = plaintext.clone();
    for field in ["dataset_bindings", "source_lineage"] {
        let Some(entries) = plaintext.get(field).and_then(Value::as_array) else {
            continue;
        };
        if entries.len() <= 16 {
            continue;
        }
        let commitment = commitments.get(field).ok_or_else(|| {
            session_error(
                "tn_session_state",
                "verified provenance commitment is unavailable",
            )
        })?;
        presentation.insert(
            field.into(),
            json!({
                "schema":"tn.governance-reference.v1", "source_object_id":source_object_id,
                "field":field, "entry_count":entries.len(), "field_commitment":commitment,
            }),
        );
    }
    Ok(presentation)
}

pub struct ParsedToolCall<'a> {
    pub id: &'a [u8],
    pub name: &'a [u8],
    pub parsed_arguments: &'a [u8],
}

pub struct NativeToolResult<'a> {
    pub call_count: usize,
    pub call: Option<ParsedToolCall<'a>>,
    pub content: &'a [u8],
    pub raw_model_output: &'a [u8],
    pub truncated: bool,
    pub stop_limit: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct AcceptedCall<'a> {
    pub runtime: bool,
    pub id: &'a str,
    pub name: &'a str,
    pub arguments: &'a str,
}

/// A required call has no model decision when both its name and argument object
/// are fixed by the offered schema. Unknown constraints retain model dispatch.
pub(crate) fn determined_tool_call(tools: &[Value]) -> Option<(String, String)> {
    let [tool] = tools else { return None };
    let function = tool.get("function")?.as_object()?;
    let schema = function.get("parameters")?.as_object()?;
    if schema.get("type")? != "object"
        || schema.get("additionalProperties")? != false
        || !schema.get("properties")?.as_object()?.is_empty()
        || schema
            .get("required")
            .is_some_and(|required| !required.as_array().is_some_and(Vec::is_empty))
        || schema.keys().any(|name| {
            !matches!(
                name.as_str(),
                "type"
                    | "properties"
                    | "additionalProperties"
                    | "required"
                    | "description"
                    | "title"
            )
        })
    {
        return None;
    }
    Some((function.get("name")?.as_str()?.to_owned(), "{}".into()))
}

pub(crate) fn section_selection_body(
    user_content: &str,
    available_sections: &BTreeMap<String, Vec<String>>,
    governance: &BTreeMap<String, Value>,
    max_tokens: u32,
) -> Result<Vec<u8>, TnLlamaError> {
    let selection = canonical_text(&json!({
        "phase": "section_selection",
        "user_request": user_content,
        "available_sections": available_sections,
        "applicable_source_governance": governance,
    }))?;
    let section_names = available_sections.keys().cloned().collect::<Vec<_>>();
    canonical_value(&json!({
        "cache_prompt": false,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": SYSTEM_CONTENT},
            {"role": "user", "content": selection}
        ],
        "n": 1,
        "n_cache_reuse": 0,
        "parallel_tool_calls": false,
        "reasoning_effort": "none",
        "stream": false,
        "temperature": 0,
        "tool_choice": "required",
        "tools": [{
            "type": "function",
            "function": {
                "name": "select_sections",
                "description": "Select every available input section needed to answer the held user request.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "sections": {
                            "type": "array",
                            "items": {"type": "string", "enum": section_names},
                            "minItems": 1,
                            "uniqueItems": true
                        }
                    },
                    "required": ["sections"],
                    "additionalProperties": false
                }
            }
        }]
    }))
}

/// The governed object stays encrypted here. The context carries the governance
/// and the hash keys; the model asks the runtime to decrypt by presenting them.
pub(crate) fn decrypt_turn_body(
    user_content: &str,
    encrypted_data: &BTreeMap<String, BTreeMap<String, String>>,
    governance_hash: &str,
    governance: &BTreeMap<String, Value>,
    max_tokens: u32,
) -> Result<Vec<u8>, TnLlamaError> {
    let encrypted_data = encrypted_data
        .iter()
        .flat_map(|(group, fields)| {
            fields.iter().map(move |(field, hash)| {
                json!({"group": group, "field": field, "data_hash": hash})
            })
        })
        .collect::<Vec<_>>();
    let control = canonical_text(&json!({
        "phase": "decrypt",
        "user_request": user_content,
        "encrypted_data": encrypted_data,
        "governance_hash": governance_hash,
        "applicable_source_governance": governance,
        "output_instruction": "The data is encrypted and you can decrypt it. Call decrypt_value. Copy governance_hash exactly. Copy into data_hashes the data_hash of each encrypted_data entry you need.",
    }))?;
    canonical_value(&json!({
        "cache_prompt": false,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": SYSTEM_CONTENT},
            {"role": "user", "content": control}
        ],
        "n": 1,
        "n_cache_reuse": 0,
        "parallel_tool_calls": false,
        "reasoning_effort": "none",
        "stream": false,
        "temperature": 0,
        "tool_choice": "required",
        "tools": [{
            "type": "function",
            "function": {
                "name": "decrypt_value",
                "description": "Decrypt governed data using the hash key of its governance object and the hash keys of the encrypted data.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "governance_hash": {"type": "string", "pattern": HASH_KEY_PATTERN},
                        "data_hashes": {
                            "type": "array",
                            "items": {"type": "string", "pattern": HASH_KEY_PATTERN},
                            "minItems": 1,
                            "uniqueItems": true
                        }
                    },
                    "required": ["governance_hash", "data_hashes"],
                    "additionalProperties": false
                }
            }
        }]
    }))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn governed_object_action_body(
    user_content: &str,
    selected: &BTreeMap<String, Value>,
    governance_hash: &str,
    decrypt_call: AcceptedCall<'_>,
    governance: &BTreeMap<String, Value>,
    report_policy: Option<&tn_core::governed::Governance>,
    attributions: &[String],
    source_object_id: &str,
    action: &str,
    tools: Vec<Value>,
    tool_exchanges: &[ToolExchange<'_>],
    max_tokens: u32,
) -> Result<Vec<u8>, TnLlamaError> {
    let required_tools = tools
        .iter()
        .filter(|tool| tool["function"]["name"] != "emit_governed_record")
        .map(|tool| tool["function"]["name"].clone())
        .collect::<Vec<_>>();
    let mut messages = vec![
        json!({"role":"system","content":SYSTEM_CONTENT}),
        json!({"role":"user","content":canonical_text(&json!({
        "phase":"governed_action", "user_request":user_content,
        "applicable_source_governance":governance, "required_attributions":attributions,
        "source_object_id":source_object_id, "operation":action,
        "required_tools":required_tools,
        "additional_report_contract": report_policy.map(|policy| json!({"governed_by":policy.governed_by(),"fields":policy.fields()})),
        "output_instruction":"Call the required tools using the business arguments in their schemas. The runtime binds each invocation to the admitted source and authorized action. When emission is offered, write report_html only and use the authenticated tool results when relevant. The runtime retains and signs every inherited contract, dataset binding, exact input source, and accepted tool publication."
    }))?}),
        assistant_call_message(decrypt_call),
        json!({"role":"tool", "tool_call_id":decrypt_call.id, "content":canonical_text(&json!({
            "data":selected, "governance_hash":governance_hash,
        }))?}),
    ];
    for exchange in tool_exchanges {
        if exchange.call.runtime {
            messages.push(runtime_result_message(exchange.call, exchange.result));
            continue;
        }
        messages.push(assistant_call_message(exchange.call));
        messages.push(
            json!({"role":"tool", "tool_call_id":exchange.call.id, "content":exchange.result}),
        );
    }
    canonical_value(&json!({
        "cache_prompt":false, "max_tokens":max_tokens, "n":1, "n_cache_reuse":0,
        "parallel_tool_calls":false, "reasoning_effort":"none", "stream":false, "temperature":0, "tool_choice":"required",
        "messages":messages,
        "tools":tools
    }))
}

pub(crate) fn native_report_tool() -> Value {
    json!({"type":"function","function":{"name":"emit_governed_record",
        "description":"Submit report content for native governed release.",
        "parameters":{"type":"object","properties":{"report_html":{"type":"string","minLength":1}},
            "required":["report_html"],"additionalProperties":false}}})
}

pub(crate) struct ToolExchange<'a> {
    pub call: AcceptedCall<'a>,
    pub result: &'a str,
}

pub(crate) struct GovernedActionBodyInput<'a> {
    pub user_content: &'a str,
    pub available_sections: &'a BTreeMap<String, Vec<String>>,
    pub selected_values: &'a BTreeMap<String, Value>,
    pub selected_sections: &'a [String],
    pub applicable_governance: Option<&'a BTreeMap<String, Value>>,
    pub output_event_type: &'a str,
    pub output_public_section: &'a str,
    pub operation: &'a str,
    pub output_policy: &'a OutputPolicy,
    pub required_attributions: &'a [String],
    pub source_lineage: Option<&'a SourceLineage>,
    pub selection_call: AcceptedCall<'a>,
    pub tool_exchanges: &'a [ToolExchange<'a>],
    pub tools: Vec<Value>,
    pub max_tokens: u32,
}

pub(crate) fn governed_action_body(
    input: GovernedActionBodyInput<'_>,
) -> Result<Vec<u8>, TnLlamaError> {
    let selection_request = canonical_text(&json!({
        "phase": "section_selection",
        "user_request": input.user_content,
        "available_sections": input.available_sections,
    }))?;
    let selection_result = canonical_text(&json!({
        "accepted": true,
        "selected_sections": input.selected_sections,
    }))?;
    let mut governed_context = Map::new();
    governed_context.insert("phase".to_string(), json!("governed_action"));
    governed_context.insert("user_request".to_string(), json!(input.user_content));
    governed_context.insert("selected_values".to_string(), json!(input.selected_values));
    governed_context.insert("operation".to_string(), json!(input.operation));
    governed_context.insert(
        "output_contract".to_string(),
        json!({
            "event_type": input.output_event_type,
            "public_section": input.output_public_section,
            "policy": {
                "instruction": input.output_policy.instruction,
                "use_for": input.output_policy.use_for,
                "do_not_use_for": input.output_policy.do_not_use_for,
                "consequences": input.output_policy.consequences,
                "on_violation_or_error": input.output_policy.on_violation_or_error,
            },
            "required_attributions": input.required_attributions,
        }),
    );
    if let Some(governance) = input.applicable_governance {
        governed_context.insert(
            "applicable_source_governance".to_string(),
            json!(governance),
        );
    }
    if let Some(lineage) = input.source_lineage {
        governed_context.insert("required_source_lineage".to_string(), json!(lineage));
    }
    let governed_context = canonical_text(&Value::Object(governed_context))?;

    let mut messages = vec![json!({"role": "system", "content": SYSTEM_CONTENT})];
    if input.selection_call.runtime {
        messages.push(runtime_result_message(
            input.selection_call,
            &selection_result,
        ));
    } else {
        messages.extend([
            json!({"role": "user", "content": selection_request}),
            assistant_call_message(input.selection_call),
            json!({
                "role": "tool",
                "tool_call_id": input.selection_call.id,
                "content": selection_result
            }),
        ]);
    }
    messages.push(json!({"role": "user", "content": governed_context}));
    for exchange in input.tool_exchanges {
        if exchange.call.runtime {
            messages.push(runtime_result_message(exchange.call, exchange.result));
            continue;
        }
        messages.push(assistant_call_message(exchange.call));
        messages.push(json!({
            "role": "tool",
            "tool_call_id": exchange.call.id,
            "content": exchange.result,
        }));
    }

    canonical_value(&json!({
        "cache_prompt": false,
        "max_tokens": input.max_tokens,
        "messages": messages,
        "n": 1,
        "n_cache_reuse": 0,
        "parallel_tool_calls": false,
        "reasoning_effort": "none",
        "stream": false,
        "temperature": 0,
        "tool_choice": "required",
        "tools": input.tools,
    }))
}

fn runtime_result_message(call: AcceptedCall<'_>, result: &str) -> Value {
    json!({"role":"user", "content": json!({
        "runtime_action": call.name, "action_id": call.id,
        "arguments": serde_json::from_str::<Value>(call.arguments).expect("validated arguments"),
        "result": serde_json::from_str::<Value>(result).expect("runtime result JSON"),
    }).to_string()})
}


fn assistant_call_message(call: AcceptedCall<'_>) -> Value {
    json!({
        "role": "assistant",
        "tool_calls": [{
            "id": call.id,
            "type": "function",
            "function": {"name": call.name, "arguments": call.arguments}
        }]
    })
}

pub(crate) fn governance_context_digest(
    context: &BTreeMap<String, Value>,
) -> Result<String, TnLlamaError> {
    Ok(digest_bytes(
        b"tn.llama.governance-context.v1\0",
        &canonical_value(&json!(context))?,
    ))
}

pub(crate) fn digest_bytes(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

pub(crate) fn model_request_digest(body: &[u8]) -> String {
    digest_bytes(MODEL_REQUEST_DIGEST_DOMAIN, body)
}

pub(crate) fn rendered_prompt_digest(prompt: &[u8]) -> String {
    digest_bytes(RENDERED_PROMPT_DIGEST_DOMAIN, prompt)
}

pub(crate) fn parse_and_digest_manifest(
    raw: &[u8],
    phase: Phase,
    expected_n_predict: u32,
) -> Result<String, TnLlamaError> {
    let value =
        crate::envelope::parse_duplicate_safe_json(raw).map_err(|_| runnable_manifest_error())?;
    let manifest: RunnableManifest =
        serde_json::from_value(value.clone()).map_err(|_| runnable_manifest_error())?;
    manifest.validate(phase, expected_n_predict)?;
    let canonical = tn_core::canonical::canonical_bytes(&value).map_err(|_| {
        session_error(
            "tn_runnable_manifest_invalid",
            "runnable manifest cannot be canonically serialized",
        )
    })?;
    Ok(digest_bytes(RUNNABLE_TASK_DIGEST_DOMAIN, &canonical))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunnableManifest {
    schema: String,
    effective_ctx_shift: bool,
    task: RunnableTask,
    params: RunnableParams,
    sampling_native: SamplingNative,
    speculative: Speculative,
    chat_parser: ChatParser,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunnableTask {
    #[serde(rename = "type")]
    task_type: String,
    tokens: Vec<i64>,
    tokens_has_mtmd: bool,
    id_slot: i64,
    index: u64,
    id_parent: i64,
    child_count: u64,
    cli: bool,
    cli_prompt_byte_length: u64,
    cli_file_count: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunnableParams {
    stream: bool,
    cache_prompt: bool,
    n_cache_reuse: i64,
    n_cmpl: i64,
    n_predict: i64,
    n_keep: i64,
    n_discard: i64,
    n_indent: i64,
    t_max_predict_ms: i64,
    lora: Vec<Value>,
    stop: Vec<String>,
    response_fields: Vec<String>,
    post_sampling_probs: bool,
    res_type: String,
    upstream_params_json: Map<String, Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SamplingNative {
    n_prev: i64,
    logit_bias_eog: Vec<Value>,
    grammar_type: String,
    sampling_generation_prompt: String,
    reasoning_budget_tokens: i64,
    reasoning_budget_start: Vec<i64>,
    reasoning_budget_end: Vec<Vec<i64>>,
    reasoning_budget_forced: Vec<i64>,
    reasoning_budget_message: String,
    reasoning_control: bool,
    backend_sampling: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Speculative {
    types: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChatParser {
    format: String,
    reasoning_format: String,
    reasoning_in_content: bool,
    generation_prompt: String,
    parse_tool_calls: bool,
    is_continuation: bool,
    echo: bool,
    debug: bool,
}

impl RunnableManifest {
    fn validate(&self, _phase: Phase, expected_n_predict: u32) -> Result<(), TnLlamaError> {
        let _recorded_but_not_restricted = (
            self.task.index,
            self.params.n_keep,
            self.params.n_discard,
            self.params.n_indent,
            self.params.t_max_predict_ms,
            &self.params.stop,
            &self.params.response_fields,
            self.params.post_sampling_probs,
            &self.params.upstream_params_json,
            self.sampling_native.n_prev,
            &self.sampling_native.logit_bias_eog,
            &self.sampling_native.grammar_type,
            &self.sampling_native.sampling_generation_prompt,
            self.sampling_native.reasoning_budget_tokens,
            &self.sampling_native.reasoning_budget_start,
            &self.sampling_native.reasoning_budget_end,
            &self.sampling_native.reasoning_budget_forced,
            &self.sampling_native.reasoning_budget_message,
            self.sampling_native.reasoning_control,
            self.sampling_native.backend_sampling,
            &self.chat_parser.format,
            &self.chat_parser.reasoning_format,
            self.chat_parser.reasoning_in_content,
            &self.chat_parser.generation_prompt,
            self.chat_parser.parse_tool_calls,
            self.chat_parser.is_continuation,
            self.chat_parser.echo,
            self.chat_parser.debug,
        );
        let valid = self.schema == RUNNABLE_TASK_SCHEMA
            && !self.effective_ctx_shift
            && self.task.task_type == "completion"
            && !self.task.tokens.is_empty()
            && !self.task.tokens_has_mtmd
            && self.task.id_slot == -1
            && self.task.id_parent == -1
            && self.task.child_count == 0
            && !self.task.cli
            && self.task.cli_prompt_byte_length == 0
            && self.task.cli_file_count == 0
            && !self.params.stream
            && !self.params.cache_prompt
            && self.params.n_cache_reuse == 0
            && self.params.n_cmpl == 1
            && self.params.n_predict == i64::from(expected_n_predict)
            && self.params.lora.is_empty()
            && self.params.res_type == "oai_chat"
            && self.speculative.types == ["none"];
        if valid {
            Ok(())
        } else {
            Err(runnable_manifest_error())
        }
    }
}

fn canonical_value(value: &Value) -> Result<Vec<u8>, TnLlamaError> {
    tn_core::canonical::canonical_bytes(value).map_err(|_| {
        session_error(
            "tn_session_state",
            "model request could not be canonically serialized",
        )
    })
}

fn canonical_text(value: &Value) -> Result<String, TnLlamaError> {
    String::from_utf8(canonical_value(value)?).map_err(|_| {
        session_error(
            "tn_session_state",
            "canonical model control data is not UTF-8",
        )
    })
}

fn runnable_manifest_error() -> TnLlamaError {
    session_error(
        "tn_runnable_manifest_invalid",
        "runnable manifest does not match the closed version-1 task projection",
    )
}

pub(crate) fn session_error(code: &'static str, message: &'static str) -> TnLlamaError {
    TnLlamaError::new(code, AdmissionStage::Session, message)
}

#[cfg(test)]
mod presentation_tests {
    use super::*;

    #[test]
    fn reference_presentation_retains_every_nonstructural_field() {
        let plaintext: BTreeMap<String, Value> = [
            (
                "dataset_bindings".into(),
                json!((0..3126).collect::<Vec<_>>()),
            ),
            ("source_lineage".into(), json!([{"object_id":"source"}])),
            ("instruction".into(), json!("Retain source conditions.")),
            (
                "attached_policies".into(),
                json!([{"fields":{"use_for":"Research"}}]),
            ),
            (
                "claims".into(),
                json!([{"issuer":"authority", "statement":"Review first"}]),
            ),
            ("custom_condition".into(), json!({"purpose":"analysis"})),
        ]
        .into();
        let commitments = plaintext
            .keys()
            .map(|name| (name.clone(), format!("hash:{name}")))
            .collect();
        let presented = governance_presentation(&plaintext, &commitments, "sha256:input").unwrap();
        for (name, value) in &plaintext {
            if name != "dataset_bindings" {
                assert_eq!(&presented[name], value);
            }
        }
        assert_eq!(presented["dataset_bindings"]["entry_count"], 3126);
        assert_eq!(
            presented["dataset_bindings"]["source_object_id"],
            "sha256:input"
        );
        assert_eq!(
            presented["dataset_bindings"]["field_commitment"],
            "hash:dataset_bindings"
        );
        assert!(serde_json::to_vec(&presented).unwrap().len() < 1000);
        assert_eq!(
            plaintext["dataset_bindings"].as_array().unwrap().len(),
            3126
        );
    }
}

#[cfg(test)]
mod determined_actions {
    use super::*;

    fn tool(name: &str, parameters: Value) -> Value {
        json!({"type":"function", "function":{"name":name,"parameters":parameters}})
    }

    #[test]
    fn a_required_parameterless_call_is_determined_by_its_schema() {
        let parameters = json!({"type":"object","properties":{},"additionalProperties":false});
        for name in ["register_review", "retain_receipt", "record_dispatch"] {
            assert_eq!(
                determined_tool_call(&[tool(name, parameters.clone())]),
                Some((name.into(), "{}".into()))
            );
        }
    }

    #[test]
    fn alternative_actions_business_arguments_and_unknown_constraints_require_decisions() {
        let empty = json!({"type":"object","properties":{},"additionalProperties":false});
        assert!(determined_tool_call(&[
            tool("first", empty.clone()),
            tool("second", empty.clone())
        ])
        .is_none());
        for schema in [
            json!({"type":"object","properties":{"purpose":{"type":"string"}},"required":["purpose"],"additionalProperties":false}),
            json!({"type":"object","properties":{"comment":{"type":"string"}},"additionalProperties":false}),
            json!({"type":"object","properties":{}}),
            json!({"type":"object","properties":{},"additionalProperties":true}),
            json!({"type":"object","properties":{},"additionalProperties":false,"minProperties":1}),
            json!({"type":"object","properties":{},"additionalProperties":false,"required":["missing"]}),
            json!({"type":"object","properties":{},"additionalProperties":false,"$ref":"#/$defs/arguments"}),
        ] {
            assert!(determined_tool_call(&[tool("action", schema)]).is_none());
        }
        assert!(determined_tool_call(&[native_report_tool()]).is_none());
        assert!(determined_tool_call(&[]).is_none());
    }
}
