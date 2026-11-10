//! Internal service bridge. All TN transitions and cryptographic operations live in Rust.
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use tn_runtime::{
    ActionOutcome, ExecutionBackend, GovernedRuntime, NativeToolResult, ParsedToolCall, Phase,
    RuntimeConfig, State,
};

fn native_error(error: tn_runtime::TnLlamaError) -> PyErr {
    PyValueError::new_err(format!("{}: {error}", error.code()))
}

#[pyclass(name = "VllmBackend", frozen)]
struct Backend(tn_runtime::VllmBackend);
#[pymethods]
impl Backend {
    #[new]
    fn new(
        engine_instance: &str,
        model_bundle_sha256: &str,
        tokenizer_sha256: &str,
        template_sha256: &str,
        parser: &str,
        vllm_revision: &str,
    ) -> PyResult<Self> {
        tn_runtime::VllmBackend::new(
            engine_instance,
            model_bundle_sha256,
            tokenizer_sha256,
            template_sha256,
            parser,
            vllm_revision,
        )
        .map(Self)
        .map_err(native_error)
    }
}

#[pyclass(name = "Runtime", frozen)]
struct Runtime(GovernedRuntime);
#[pymethods]
impl Runtime {
    #[new]
    fn new(py: Python<'_>, config_json: &[u8], backend: &Backend) -> PyResult<Self> {
        let config: RuntimeConfig = serde_json::from_slice(config_json)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let selected = ExecutionBackend::Vllm(backend.0.clone());
        py.allow_threads(move || GovernedRuntime::from_config_with_backend(config, selected))
            .map(Self)
            .map_err(native_error)
    }
    fn start_session(&self, py: Python<'_>, request_json: &[u8]) -> PyResult<NativeSession> {
        py.allow_threads(|| self.0.start_session(request_json))
            .map(NativeSession)
            .map_err(native_error)
    }
}

#[pyclass(name = "Session")]
struct NativeSession(tn_runtime::Session);
#[pymethods]
impl NativeSession {
    fn next_turn(&mut self, py: Python<'_>) -> PyResult<NativeTurn> {
        py.allow_threads(|| self.0.next_model_turn())
            .map(|turn| NativeTurn {
                request_json: turn.request_json,
                permit: Some(turn.permit),
            })
            .map_err(native_error)
    }
    #[getter]
    fn state(&self) -> &'static str {
        match self.0.state() {
            State::GovernanceAdmission => "governance_admission",
            State::SectionSelection => "section_selection",
            State::GovernedAction => "governed_action",
            State::Complete => "complete",
            State::Failed => "failed",
        }
    }
    #[pyo3(signature=(turn,calls,content,raw_output,truncated=false,stop_limit=false))]
    fn accept(
        &mut self,
        py: Python<'_>,
        mut turn: PyRefMut<'_, NativeTurn>,
        calls: Vec<Py<ToolCall>>,
        content: &[u8],
        raw_output: &[u8],
        truncated: bool,
        stop_limit: bool,
    ) -> PyResult<Option<Py<PyBytes>>> {
        let permit = turn
            .permit
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("turn already consumed"))?;
        let calls: Vec<ToolCall> = calls.iter().map(|call| call.borrow(py).clone()).collect();
        let result = NativeToolResult {
            call_count: calls.len(),
            call: calls.first().map(|call| ParsedToolCall {
                id: call.id.as_bytes(),
                name: call.name.as_bytes(),
                parsed_arguments: &call.arguments,
            }),
            content,
            raw_model_output: raw_output,
            truncated,
            stop_limit,
        };
        let outcome = py
            .allow_threads(|| self.0.accept_model_action(permit, result))
            .map_err(native_error)?;
        let released = match outcome {
            ActionOutcome::Continue => return Ok(None),
            ActionOutcome::GovernedRelease(value) => value.to_json_bytes(),
        }
        .map_err(native_error)?;
        Ok(Some(PyBytes::new(py, &released).unbind()))
    }
    fn abort(&mut self, py: Python<'_>) -> PyResult<()> {
        py.allow_threads(|| self.0.abort()).map_err(native_error)
    }
}

#[pyclass(name = "ModelTurn")]
struct NativeTurn {
    request_json: Vec<u8>,
    permit: Option<tn_runtime::TurnPermit>,
}
impl NativeTurn {
    fn permit(&self) -> PyResult<&tn_runtime::TurnPermit> {
        self.permit
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("turn already consumed"))
    }
}
#[pymethods]
impl NativeTurn {
    #[getter]
    fn request_json(&self, py: Python<'_>) -> Py<PyBytes> {
        PyBytes::new(py, &self.request_json).unbind()
    }
    #[getter]
    fn phase(&self) -> PyResult<&'static str> {
        Ok(match self.permit()?.phase() {
            Phase::GovernanceRead => "governance_read",
            Phase::CommitmentEcho => "commitment_echo",
            Phase::SectionSelection => "section_selection",
            Phase::GovernedAction => "governed_action",
        })
    }
    fn prepare(
        &self,
        py: Python<'_>,
        rendered_prompt: &[u8],
        manifest_json: &[u8],
    ) -> PyResult<()> {
        let permit = self.permit()?;
        py.allow_threads(|| permit.prepare(&self.request_json, rendered_prompt, manifest_json))
            .map_err(native_error)
    }
    fn begin(
        &self,
        py: Python<'_>,
        rendered_prompt: &[u8],
        manifest_json: &[u8],
        identity_json: &[u8],
    ) -> PyResult<()> {
        let identity = serde_json::from_slice(identity_json)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        let permit = self.permit()?;
        py.allow_threads(|| {
            permit.begin_vllm(identity, &self.request_json, rendered_prompt, manifest_json)
        })
        .map_err(native_error)
    }
}

#[pyclass(frozen)]
#[derive(Clone)]
struct ToolCall {
    #[pyo3(get)]
    id: String,
    #[pyo3(get)]
    name: String,
    arguments: Vec<u8>,
}
#[pymethods]
impl ToolCall {
    #[new]
    fn new(id: String, name: String, arguments: Vec<u8>) -> Self {
        Self {
            id,
            name,
            arguments,
        }
    }
    #[getter]
    fn arguments(&self, py: Python<'_>) -> Py<PyBytes> {
        PyBytes::new(py, &self.arguments).unbind()
    }
}

#[pymodule]
fn tn_runtime_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Backend>()?;
    m.add_class::<Runtime>()?;
    m.add_class::<NativeSession>()?;
    m.add_class::<NativeTurn>()?;
    m.add_class::<ToolCall>()?;
    m.add("VLLM_REVISION", tn_runtime::VLLM_REVISION)?;
    m.add("SAMPLING_FIELDS", tn_runtime::SAMPLING_FIELDS.to_vec())?;
    m.add("__version__", "2026.9.11b1")?;
    Ok(())
}
