use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde_json::{json, Value};

use crate::error::{AdmissionStage, TnLlamaError};
use crate::strict_json::parse_duplicate_safe_json;

/// Names the governed model protocol reserves for its own decrypt and report calls.
const RESERVED_TOOL_NAMES: [&str; 2] = ["decrypt_value", "emit_governed_record"];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredCall {
    pub id: String,
    pub name: String,
    pub arguments: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredToolSpec {
    name: String,
    description: String,
    parameters: Value,
}

impl RegisteredToolSpec {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    #[must_use]
    pub fn parameters(&self) -> &Value {
        &self.parameters
    }

    pub(crate) fn native_model_tool(&self) -> Value {
        json!({"type":"function", "function":{"name":self.name, "description":self.description, "parameters":self.parameters}})
    }
}

pub struct ToolDispatcher {
    specs: BTreeMap<String, RegisteredToolSpec>,
    native_publisher: Option<Arc<crate::output_tn::GovernedOutputPublisher>>,
}

/// Session-owned context: no caller or model can construct an accepted native invocation.
pub(crate) struct NativeToolContext<'a> {
    pub run_id: &'a str,
    pub data: &'a tn_core::governed::DataObject,
    pub request: &'a crate::AcceptedGovernedRequest,
    pub source: &'a tn_core::governed::GovernanceView,
    pub input: &'a crate::governed_input::GovernedInputRuntime,
    pub selected_sections: &'a BTreeSet<String>,
    pub action: &'a str,
}

pub(crate) struct NativeToolReceipt {
    pub publication: crate::output_tn::GovernedPublication,
    pub receipt: Value,
}

impl ToolDispatcher {
    pub(crate) fn empty() -> Self {
        Self {
            specs: BTreeMap::new(),
            native_publisher: None,
        }
    }

    pub(crate) fn native(
        publisher: Arc<crate::output_tn::GovernedOutputPublisher>,
        configured_name: &str,
    ) -> Result<Self, TnLlamaError> {
        if configured_name.trim().is_empty() || RESERVED_TOOL_NAMES.contains(&configured_name) {
            return Err(tool_error(
                "tn_tool_registration_invalid",
                "protected tool name conflicts with the governed model protocol",
            ));
        }
        let spec = RegisteredToolSpec {
            name: configured_name.into(),
            description: "Record governed report creation through the native TN publisher and return its authenticated receipt.".into(),
            parameters: json!({"type":"object", "properties":{}, "additionalProperties":false}),
        };
        Ok(Self {
            specs: BTreeMap::from([(configured_name.into(), spec)]),
            native_publisher: Some(publisher),
        })
    }

    pub(crate) fn execute_native(
        &self,
        call: &RegisteredCall,
        context: &NativeToolContext<'_>,
    ) -> Result<NativeToolReceipt, TnLlamaError> {
        let publisher = self
            .native_publisher
            .as_ref()
            .filter(|_| self.specs.contains_key(&call.name))
            .ok_or_else(|| {
                tool_error(
                    "tn_tool_not_registered",
                    "native protected tool is not registered",
                )
            })?;
        let value = parse_duplicate_safe_json(&call.arguments).map_err(|_| arguments_error())?;
        if !value
            .as_object()
            .is_some_and(|arguments| arguments.is_empty())
            || call.id.trim().is_empty()
            || context.action != context.request.use_context.operation()
            || context.selected_sections.is_empty()
        {
            return Err(arguments_error());
        }
        let content = json!({
            "run_id":context.run_id, "request_digest":context.request.request_digest,
            "tool_name":call.name, "model_tool_call_id":call.id,
            "source_object_id":context.request.object.id(),
            "source_writer":context.request.object.writer(),
            "source_type":context.request.object.object_type(),
            "selected_sections":context.selected_sections, "action":context.action,
        });
        let publication = publisher.publish(
            context.data.clone(),
            content.clone(),
            "compliance.creation.logged",
            context.request,
            &[context.source],
            context.input,
            false,
        )?;
        let mut receipt = content;
        receipt["output_object_id"] = json!(publication.object.id());
        receipt["output_object_type"] = json!(publication.object.object_type());
        Ok(NativeToolReceipt {
            publication,
            receipt,
        })
    }

    #[must_use]
    pub fn specification(&self, name: &str) -> Option<&RegisteredToolSpec> {
        self.specs.get(name)
    }

    pub fn specifications(&self) -> impl Iterator<Item = &RegisteredToolSpec> {
        self.specs.values()
    }
}

fn arguments_error() -> TnLlamaError {
    tool_error(
        "tn_tool_arguments_invalid",
        "governed tool arguments must be an empty object bound to the admitted action",
    )
}

fn tool_error(code: &'static str, message: &'static str) -> TnLlamaError {
    TnLlamaError::new(code, AdmissionStage::Tool, message)
}
