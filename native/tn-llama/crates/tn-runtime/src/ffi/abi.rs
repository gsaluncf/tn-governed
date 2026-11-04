//! The C ABI's handles and byte views, and marshalling that keeps errors and panics inside it.
use std::mem;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr::{self, null_mut};

use serde_json::json;

use crate::model_protocol::session_error;
use crate::{AdmissionStage, GovernedRuntime, Phase, Session, TnLlamaError, TurnPermit};

pub(super) const STATUS_OK: i32 = 0;
pub(super) const STATUS_ERROR: i32 = 1;
pub(super) const STATUS_PANIC: i32 = 2;
pub(super) const PANIC_ERROR_JSON: &[u8] =
    br#"{"code":"tn_ffi_panic","stage":"ffi","message":"panic contained at the C ABI boundary"}"#;

pub(crate) struct RuntimeHandle(pub(super) GovernedRuntime);
pub(crate) struct SessionHandle(pub(super) Session);
pub(crate) struct TurnHandle(pub(super) Option<TurnPermit>);

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct BytesView {
    pub(super) ptr: *const u8,
    pub(super) len: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct OwnedBytes {
    pub(super) ptr: *mut u8,
    pub(super) len: usize,
}

#[repr(C)]
pub(crate) struct NativeToolCall {
    pub(super) id: BytesView,
    pub(super) name: BytesView,
    pub(super) normalized_arguments: BytesView,
}

#[repr(C)]
pub(crate) struct NativeToolResultInput {
    pub(super) call_count: usize,
    pub(super) call: *const NativeToolCall,
    pub(super) content: BytesView,
    pub(super) raw_model_output: BytesView,
    pub(super) truncated: u8,
    pub(super) stop_limit: u8,
}

impl OwnedBytes {
    pub(super) const EMPTY: Self = Self {
        ptr: null_mut(),
        len: 0,
    };

    pub(super) fn from_vec(bytes: Vec<u8>) -> Self {
        if bytes.is_empty() {
            return Self::EMPTY;
        }
        let mut bytes = bytes.into_boxed_slice();
        let value = Self {
            ptr: bytes.as_mut_ptr(),
            len: bytes.len(),
        };
        mem::forget(bytes);
        value
    }
}

pub(super) fn catch_ffi<I, F>(out_error: *mut OwnedBytes, initialize: I, operation: F) -> i32
where
    I: FnOnce() -> Result<(), TnLlamaError>,
    F: FnOnce() -> Result<(), TnLlamaError>,
{
    let mut panic_error = OwnedBytes::EMPTY;
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        if !out_error.is_null() {
            unsafe {
                *out_error = OwnedBytes::EMPTY;
            }
            panic_error = OwnedBytes::from_vec(PANIC_ERROR_JSON.to_vec());
        }
        let initialized = initialize();
        if out_error.is_null() {
            return STATUS_ERROR;
        }
        let status = match initialized.and_then(|()| operation()) {
            Ok(()) => STATUS_OK,
            Err(error) => {
                publish_error(out_error, &error);
                STATUS_ERROR
            }
        };
        drop_owned_bytes(&mut panic_error);
        status
    }));
    match outcome {
        Ok(status) => status,
        Err(_) => {
            if !out_error.is_null() && !panic_error.ptr.is_null() {
                unsafe {
                    *out_error = mem::replace(&mut panic_error, OwnedBytes::EMPTY);
                }
            }
            STATUS_PANIC
        }
    }
}

pub(super) fn publish_error(out_error: *mut OwnedBytes, error: &TnLlamaError) {
    let bytes = serde_json::to_vec(&json!({
        "code": error.code(),
        "stage": stage_name(error.stage()),
        "message": error.message(),
    }))
    .expect("strings always serialize to JSON");
    unsafe {
        *out_error = OwnedBytes::from_vec(bytes);
    }
}

pub(super) fn drop_owned_bytes(value: &mut OwnedBytes) {
    let owned = mem::replace(value, OwnedBytes::EMPTY);
    if owned.ptr.is_null() || owned.len == 0 {
        return;
    }
    unsafe {
        let slice = ptr::slice_from_raw_parts_mut(owned.ptr, owned.len);
        drop(Box::from_raw(slice));
    }
}

pub(super) const fn phase_number(phase: Phase) -> u32 {
    match phase {
        Phase::GovernanceRead => 1,
        Phase::CommitmentEcho => 2,
        Phase::SectionSelection => 3,
        Phase::GovernedAction => 4,
    }
}

pub(super) const fn stage_name(stage: AdmissionStage) -> &'static str {
    match stage {
        AdmissionStage::Parse => "parse",
        AdmissionStage::RequestShape => "request_shape",
        AdmissionStage::RowShape => "row_shape",
        AdmissionStage::RowHash => "row_hash",
        AdmissionStage::Governance => "governance",
        AdmissionStage::Chain => "chain",
        AdmissionStage::Admission => "admission",
        AdmissionStage::Session => "session",
        AdmissionStage::Output => "output",
        AdmissionStage::Tool => "tool",
        AdmissionStage::Ffi => "ffi",
    }
}

pub(super) fn ffi_error(code: &'static str, message: impl Into<String>) -> TnLlamaError {
    TnLlamaError::new(code, AdmissionStage::Ffi, message)
}

pub(super) fn invalid_argument(message: impl Into<String>) -> TnLlamaError {
    ffi_error("tn_ffi_invalid_argument", message)
}

pub(super) fn zero_handle_output<T>(output: *mut *mut T, name: &str) -> Result<(), TnLlamaError> {
    if output.is_null() {
        return Err(invalid_argument(format!("{name} is null")));
    }
    unsafe {
        *output = null_mut();
    }
    Ok(())
}

pub(super) fn zero_action_outputs(
    out_outcome: *mut u32,
    out_release_json: *mut OwnedBytes,
) -> Result<(), TnLlamaError> {
    unsafe {
        if !out_outcome.is_null() {
            *out_outcome = 0;
        }
        if !out_release_json.is_null() {
            *out_release_json = OwnedBytes::EMPTY;
        }
    }
    if out_outcome.is_null() {
        return Err(invalid_argument("out_outcome is null"));
    }
    if out_release_json.is_null() {
        return Err(invalid_argument("out_release_json is null"));
    }
    Ok(())
}

pub(super) fn zero_u8_output(output: *mut u8, name: &str) -> Result<(), TnLlamaError> {
    if output.is_null() {
        return Err(invalid_argument(format!("{name} is null")));
    }
    unsafe {
        *output = 0;
    }
    Ok(())
}

pub(super) fn zero_next_turn_outputs(
    out_turn: *mut *mut TurnHandle,
    out_phase: *mut u32,
    out_request_json: *mut OwnedBytes,
) -> Result<(), TnLlamaError> {
    unsafe {
        if !out_turn.is_null() {
            *out_turn = null_mut();
        }
        if !out_phase.is_null() {
            *out_phase = 0;
        }
        if !out_request_json.is_null() {
            *out_request_json = OwnedBytes::EMPTY;
        }
    }
    if out_turn.is_null() {
        return Err(invalid_argument("out_turn is null"));
    }
    if out_phase.is_null() {
        return Err(invalid_argument("out_phase is null"));
    }
    if out_request_json.is_null() {
        return Err(invalid_argument("out_request_json is null"));
    }
    Ok(())
}

pub(super) fn read_view<'a>(view: BytesView, name: &str) -> Result<&'a [u8], TnLlamaError> {
    if view.ptr.is_null() {
        return if view.len == 0 {
            Ok(&[])
        } else {
            Err(invalid_argument(format!(
                "{name} has a null pointer with a nonzero length"
            )))
        };
    }
    if view.len > isize::MAX as usize {
        return Err(invalid_argument(format!("{name} is too large")));
    }
    Ok(unsafe { std::slice::from_raw_parts(view.ptr, view.len) })
}

pub(super) fn read_bool(value: u8, name: &str) -> Result<bool, TnLlamaError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid_argument(format!("{name} is not a boolean"))),
    }
}

pub(super) fn required_ref<'a, T>(value: *const T, name: &str) -> Result<&'a T, TnLlamaError> {
    unsafe { value.as_ref() }.ok_or_else(|| invalid_argument(format!("{name} is null")))
}

pub(super) fn required_mut<'a, T>(value: *mut T, name: &str) -> Result<&'a mut T, TnLlamaError> {
    unsafe { value.as_mut() }.ok_or_else(|| invalid_argument(format!("{name} is null")))
}

pub(super) fn turn_permit(turn: &TurnHandle) -> Result<&TurnPermit, TnLlamaError> {
    turn.0
        .as_ref()
        .ok_or_else(|| session_error("tn_turn_consumed", "turn permit was already consumed"))
}

pub(super) fn free_handle<T>(handle: *mut T) {
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        if !handle.is_null() {
            drop(Box::from_raw(handle));
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::super::tn_bytes_free;
    use super::*;

    #[test]
    fn catch_wrapper_contains_panics_without_exporting_a_test_hook() {
        let mut error = OwnedBytes::EMPTY;
        let status = catch_ffi(
            &mut error,
            || Ok(()),
            || -> Result<(), TnLlamaError> { panic!("private panic payload") },
        );

        assert_eq!(status, STATUS_PANIC);
        let bytes = unsafe { std::slice::from_raw_parts(error.ptr, error.len) };
        assert_eq!(bytes, PANIC_ERROR_JSON);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(bytes).unwrap(),
            json!({
                "code": "tn_ffi_panic",
                "stage": "ffi",
                "message": "panic contained at the C ABI boundary",
            })
        );
        assert!(!bytes
            .windows(b"private panic payload".len())
            .any(|window| { window == b"private panic payload" }));
        tn_bytes_free(&mut error);
        assert!(error.ptr.is_null());
        assert_eq!(error.len, 0);
    }
}
