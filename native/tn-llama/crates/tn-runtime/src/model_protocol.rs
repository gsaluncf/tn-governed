use std::collections::BTreeMap;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::{AdmissionStage, TnLlamaError};

pub const MODEL_REQUEST_DIGEST_DOMAIN: &[u8] = b"tn.llama.model-request.v1\0";
pub const RENDERED_PROMPT_DIGEST_DOMAIN: &[u8] = b"tn.llama.rendered-prompt.v1\0";

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

pub(crate) struct DecryptOffer {
    pub governance_hash: Option<String>,
    pub hashes: BTreeMap<String, String>,
}

pub(crate) fn decrypt_turn_body(
    user_content: &str,
    encrypted_data: &BTreeMap<String, DecryptOffer>,
    governance_hash: &str,
    governance: &BTreeMap<String, Value>,
    max_tokens: u32,
) -> Result<Vec<u8>, TnLlamaError> {
    let encrypted_data = encrypted_data
        .iter()
        .flat_map(|(group, offer)| {
            offer.hashes.iter().map(move |(field, hash)| {
                let mut entry = json!({"group": group, "field": field, "data_hash": hash});
                if let Some(key) = &offer.governance_hash {
                    entry["governance_hash"] = json!(key);
                }
                entry
            })
        })
        .collect::<Vec<_>>();
    let control = canonical_text(&json!({
        "phase": "decrypt",
        "user_request": user_content,
        "encrypted_data": encrypted_data,
        "governance_hash": governance_hash,
        "applicable_source_governance": governance,
        "output_instruction": "The data is encrypted and you can decrypt it. Call decrypt_value. Copy governance_hash exactly. Copy into data_hashes the data_hash of each encrypted_data entry you need. An entry that names its own governance_hash is governed by another object; decrypt it in a call that passes that governance_hash.",
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
        "description":"Submit report content for native governed release. Write report_html with only these HTML elements and no attributes, styles, or scripts: html, head, title, body, p, div, span, br, h1, h2, h3, h4, ul, ol, li, strong, b, em, i, code, pre, table, thead, tbody, tr, th, td.",
        "parameters":{"type":"object","properties":{"report_html":{"type":"string","minLength":1}},
            "required":["report_html"],"additionalProperties":false}}})
}

pub(crate) struct ToolExchange<'a> {
    pub call: AcceptedCall<'a>,
    pub result: &'a str,
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
