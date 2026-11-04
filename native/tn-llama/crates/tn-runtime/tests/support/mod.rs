#![allow(dead_code)]

use std::fs;

use serde_json::{json, Value};
use tn_runtime::{ModelTurn, NativeToolResult, ParsedToolCall, RuntimeConfig};
use tn_test_tools::RealTnFixture;

pub struct OwnedToolResult {
    pub id: Vec<u8>,
    pub name: Vec<u8>,
    pub arguments: Vec<u8>,
    pub raw: Vec<u8>,
    pub content: Vec<u8>,
    pub call_count: usize,
    pub truncated: bool,
    pub stop_limit: bool,
}

impl OwnedToolResult {
    pub fn native(&self) -> NativeToolResult<'_> {
        NativeToolResult {
            call_count: self.call_count,
            call: (self.call_count == 1).then_some(ParsedToolCall {
                id: &self.id,
                name: &self.name,
                parsed_arguments: &self.arguments,
            }),
            content: &self.content,
            raw_model_output: &self.raw,
            truncated: self.truncated,
            stop_limit: self.stop_limit,
        }
    }
}

pub fn fixture_config(fixture: &RealTnFixture) -> RuntimeConfig {
    serde_json::from_slice(&fs::read(fixture.temp.path().join("runtime-config.json")).unwrap())
        .unwrap()
}

pub fn literal_runnable_manifest(n_predict: u32) -> Vec<u8> {
    canonical_json(&json!({
        "schema": "tn.llama.runnable-task.v1",
        "effective_ctx_shift": false,
        "task": {
            "type": "completion",
            "tokens": [1, 2, -3],
            "tokens_has_mtmd": false,
            "id_slot": -1,
            "index": 0,
            "id_parent": -1,
            "child_count": 0,
            "cli": false,
            "cli_prompt_byte_length": 0,
            "cli_file_count": 0
        },
        "params": {
            "stream": false,
            "cache_prompt": false,
            "n_cache_reuse": 0,
            "n_cmpl": 1,
            "n_predict": n_predict,
            "n_keep": 0,
            "n_discard": 0,
            "n_indent": 0,
            "t_max_predict_ms": -1,
            "lora": [],
            "stop": [],
            "response_fields": [],
            "post_sampling_probs": false,
            "res_type": "oai_chat",
            "upstream_params_json": {}
        },
        "sampling_native": {
            "n_prev": 64,
            "logit_bias_eog": [],
            "grammar_type": "tool_calls",
            "sampling_generation_prompt": "",
            "reasoning_budget_tokens": -1,
            "reasoning_budget_start": [],
            "reasoning_budget_end": [],
            "reasoning_budget_forced": [],
            "reasoning_budget_message": "",
            "reasoning_control": false,
            "backend_sampling": false
        },
        "speculative": {"types": ["none"]},
        "chat_parser": {
            "format": "content_only",
            "reasoning_format": "none",
            "reasoning_in_content": false,
            "generation_prompt": "",
            "parse_tool_calls": true,
            "is_continuation": false,
            "echo": false,
            "debug": false
        }
    }))
}

pub fn canonical_json(value: &Value) -> Vec<u8> {
    tn_core::canonical::canonical_bytes(value).unwrap()
}

pub fn prepare_and_begin(turn: &ModelTurn, prompt: &[u8], n_predict: u32, task_id: i64) {
    let manifest = literal_runnable_manifest(n_predict);
    turn.permit
        .prepare(&turn.request_json, prompt, &manifest)
        .unwrap();
    turn.permit
        .begin(task_id, 0, &turn.request_json, prompt, &manifest)
        .unwrap();
}
