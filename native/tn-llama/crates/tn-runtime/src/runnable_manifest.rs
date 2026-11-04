//! The runnable task the inference process installs, projected to a closed version-1 shape.
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::model_phase::Phase;
use crate::model_protocol::{digest_bytes, session_error};
use crate::TnLlamaError;

pub const RUNNABLE_TASK_DIGEST_DOMAIN: &[u8] = b"tn.llama.runnable-task.v1\0";
pub const RUNNABLE_TASK_SCHEMA: &str = "tn.llama.runnable-task.v1";

pub(crate) fn parse_and_digest_manifest(
    raw: &[u8],
    phase: Phase,
    expected_n_predict: u32,
) -> Result<String, TnLlamaError> {
    let value = crate::strict_json::parse_duplicate_safe_json(raw)
        .map_err(|_| runnable_manifest_error())?;
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

fn runnable_manifest_error() -> TnLlamaError {
    session_error(
        "tn_runnable_manifest_invalid",
        "runnable manifest does not match the closed version-1 task projection",
    )
}
