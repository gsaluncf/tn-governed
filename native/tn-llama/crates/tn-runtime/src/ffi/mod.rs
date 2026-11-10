use std::mem;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use crate::model_protocol::session_error;
use crate::{
    governance_model_binding_authorized_from_env, governance_model_file_matches, ActionOutcome,
    GovernedRuntime, NativeToolResult, ParsedToolCall, RuntimeConfig,
};

mod abi;

use abi::*;

#[no_mangle]
pub(crate) extern "C" fn tn_governance_model_binding_authorized(
    observed_model_sha256: BytesView,
    out_authorized: *mut u8,
    out_error: *mut OwnedBytes,
) -> i32 {
    catch_ffi(
        out_error,
        || zero_u8_output(out_authorized, "out_authorized"),
        || {
            let observed = read_view(observed_model_sha256, "observed_model_sha256")?;
            let observed = std::str::from_utf8(observed)
                .map_err(|_| invalid_argument("observed_model_sha256 must contain valid UTF-8"))?;
            unsafe {
                *out_authorized = u8::from(governance_model_binding_authorized_from_env(observed));
            }
            Ok(())
        },
    )
}

#[no_mangle]
pub(crate) extern "C" fn tn_governance_model_file_authorized(
    config_json: BytesView,
    model_path: BytesView,
    out_authorized: *mut u8,
    out_error: *mut OwnedBytes,
) -> i32 {
    catch_ffi(
        out_error,
        || zero_u8_output(out_authorized, "out_authorized"),
        || {
            let config: RuntimeConfig =
                serde_json::from_slice(read_view(config_json, "config_json")?).map_err(|_| {
                    ffi_error(
                        "tn_ffi_config_invalid",
                        "runtime configuration JSON is invalid",
                    )
                })?;
            let model_path = std::str::from_utf8(read_view(model_path, "model_path")?)
                .map_err(|_| invalid_argument("model_path must contain valid UTF-8"))?;
            let expected = format!("sha256:{}", config.model_sha256);
            let authorized = governance_model_file_matches(model_path, &expected)
                .map_err(|_| ffi_error("tn_model_hash_failed", "model file could not be hashed"))?;
            unsafe {
                *out_authorized = u8::from(authorized);
            }
            Ok(())
        },
    )
}

#[no_mangle]
pub(crate) extern "C" fn tn_runtime_create(
    config_json: BytesView,
    out_runtime: *mut *mut RuntimeHandle,
    out_error: *mut OwnedBytes,
) -> i32 {
    catch_ffi(
        out_error,
        || zero_handle_output(out_runtime, "out_runtime"),
        || {
            let config_json = read_view(config_json, "config_json")?;
            let config: RuntimeConfig = serde_json::from_slice(config_json).map_err(|_| {
                ffi_error(
                    "tn_ffi_config_invalid",
                    "runtime configuration JSON is invalid",
                )
            })?;
            let runtime = RuntimeHandle(GovernedRuntime::from_config(config)?);
            unsafe {
                *out_runtime = Box::into_raw(Box::new(runtime));
            }
            Ok(())
        },
    )
}

#[no_mangle]
pub(crate) extern "C" fn tn_session_create(
    runtime: *mut RuntimeHandle,
    request_json: BytesView,
    out_session: *mut *mut SessionHandle,
    out_error: *mut OwnedBytes,
) -> i32 {
    catch_ffi(
        out_error,
        || zero_handle_output(out_session, "out_session"),
        || {
            let runtime = required_ref(runtime, "runtime")?;
            let request_json = read_view(request_json, "request_json")?;
            let session = SessionHandle(runtime.0.start_session(request_json)?);
            unsafe {
                *out_session = Box::into_raw(Box::new(session));
            }
            Ok(())
        },
    )
}

#[no_mangle]
pub(crate) extern "C" fn tn_session_next_model_turn(
    session: *mut SessionHandle,
    out_turn: *mut *mut TurnHandle,
    out_phase: *mut u32,
    out_request_json: *mut OwnedBytes,
    out_error: *mut OwnedBytes,
) -> i32 {
    catch_ffi(
        out_error,
        || zero_next_turn_outputs(out_turn, out_phase, out_request_json),
        || {
            let session = required_mut(session, "session")?;
            let model_turn = session.0.next_model_turn()?;
            let phase = phase_number(model_turn.permit.phase());
            let turn = Box::new(TurnHandle(Some(model_turn.permit)));
            let body = OwnedBytes::from_vec(model_turn.request_json);
            unsafe {
                *out_turn = Box::into_raw(turn);
                *out_phase = phase;
                *out_request_json = body;
            }
            Ok(())
        },
    )
}

#[no_mangle]
pub(crate) extern "C" fn tn_turn_prepare(
    turn: *mut TurnHandle,
    request_json: BytesView,
    rendered_prompt: BytesView,
    runnable_manifest: BytesView,
    out_error: *mut OwnedBytes,
) -> i32 {
    catch_ffi(
        out_error,
        || Ok(()),
        || {
            let turn = required_ref(turn, "turn")?;
            let request_json = read_view(request_json, "request_json")?;
            let rendered_prompt = read_view(rendered_prompt, "rendered_prompt")?;
            let runnable_manifest = read_view(runnable_manifest, "runnable_manifest")?;
            turn_permit(turn)?.prepare(request_json, rendered_prompt, runnable_manifest)
        },
    )
}

#[no_mangle]
pub(crate) extern "C" fn tn_turn_begin(
    turn: *mut TurnHandle,
    task_id: i64,
    slot_id: i32,
    request_json: BytesView,
    rendered_prompt: BytesView,
    runnable_manifest: BytesView,
    out_error: *mut OwnedBytes,
) -> i32 {
    catch_ffi(
        out_error,
        || Ok(()),
        || {
            let turn = required_ref(turn, "turn")?;
            let request_json = read_view(request_json, "request_json")?;
            let rendered_prompt = read_view(rendered_prompt, "rendered_prompt")?;
            let runnable_manifest = read_view(runnable_manifest, "runnable_manifest")?;
            turn_permit(turn)?.begin(
                task_id,
                slot_id,
                request_json,
                rendered_prompt,
                runnable_manifest,
            )
        },
    )
}

#[no_mangle]
pub(crate) extern "C" fn tn_session_accept_model_action(
    session: *mut SessionHandle,
    turn: *mut TurnHandle,
    result: *const NativeToolResultInput,
    out_outcome: *mut u32,
    out_release_json: *mut OwnedBytes,
    out_error: *mut OwnedBytes,
) -> i32 {
    catch_ffi(
        out_error,
        || zero_action_outputs(out_outcome, out_release_json),
        || {
            let session = required_mut(session, "session")?;
            let turn = required_mut(turn, "turn")?;
            let result = required_ref(result, "result")?;
            let content = read_view(result.content, "result.content")?;
            let raw_model_output = read_view(result.raw_model_output, "result.raw_model_output")?;
            let truncated = read_bool(result.truncated, "result.truncated")?;
            let stop_limit = read_bool(result.stop_limit, "result.stop_limit")?;
            let parsed_call = if result.call_count == 1 {
                let call = required_ref(result.call, "result.call")?;
                Some(ParsedToolCall {
                    id: read_view(call.id, "result.call.id")?,
                    name: read_view(call.name, "result.call.name")?,
                    parsed_arguments: read_view(
                        call.normalized_arguments,
                        "result.call.normalized_arguments",
                    )?,
                })
            } else {
                None
            };
            let permit = turn.0.take().ok_or_else(|| {
                session_error("tn_turn_consumed", "turn permit was already consumed")
            })?;
            let outcome = session.0.accept_model_action(
                permit,
                NativeToolResult {
                    call_count: result.call_count,
                    call: parsed_call,
                    content,
                    raw_model_output,
                    truncated,
                    stop_limit,
                },
            )?;
            unsafe {
                match outcome {
                    ActionOutcome::Continue => *out_outcome = 1,
                    ActionOutcome::GovernedRelease(release) => {
                        *out_outcome = 2;
                        *out_release_json = OwnedBytes::from_vec(release.to_json_bytes()?);
                    }
                }
            }
            Ok(())
        },
    )
}

#[no_mangle]
pub(crate) extern "C" fn tn_session_abort(
    session: *mut SessionHandle,
    out_error: *mut OwnedBytes,
) -> i32 {
    catch_ffi(
        out_error,
        || Ok(()),
        || {
            let session = required_mut(session, "session")?;
            session.0.abort()
        },
    )
}

#[no_mangle]
pub(crate) extern "C" fn tn_bytes_free(value: *mut OwnedBytes) {
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        let Some(value) = value.as_mut() else {
            return;
        };
        let owned = mem::replace(value, OwnedBytes::EMPTY);
        if owned.ptr.is_null() || owned.len == 0 {
            return;
        }
        let slice = ptr::slice_from_raw_parts_mut(owned.ptr, owned.len);
        drop(Box::from_raw(slice));
    }));
}

#[no_mangle]
pub(crate) extern "C" fn tn_turn_free(turn: *mut TurnHandle) {
    free_handle(turn);
}

#[no_mangle]
pub(crate) extern "C" fn tn_session_free(session: *mut SessionHandle) {
    free_handle(session);
}

#[no_mangle]
pub(crate) extern "C" fn tn_runtime_free(runtime: *mut RuntimeHandle) {
    free_handle(runtime);
}
