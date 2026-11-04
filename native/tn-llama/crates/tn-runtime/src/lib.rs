//! TN-governed llama runtime boundary.

mod admission;
mod audit;
mod client_trace;
mod config;
mod contract;
mod decision_context;
mod error;
mod execution_binding;
mod ffi;
mod governance;
mod governance_binding;
mod governed_input;
mod model_phase;
mod model_protocol;
mod output_tn;
mod reference_runs;
mod report_html;
mod runnable_manifest;
mod runtime;
mod sensitive_trace;
mod session;
mod strict_json;
mod tools;

pub use admission::AdmissionController;
pub use audit::{
    AuditDigest, AuditDigestError, AuditEvent, AuditFacts, AuditLog, AuditRecord, DecisionAudit,
    AUDIT_EVENT_TYPE, AUDIT_SCHEMA,
};
pub use client_trace::{ActionOutcome, ClientTraceEvent, GovernedReportRelease};
pub use config::{RequestLimits, RuntimeConfig};
pub use contract::{OutputPolicy, ReportContract, SectionRule};
pub use error::{AdmissionStage, TnLlamaError};
pub use governance::{
    GovernanceKeyProvenance, GovernanceReader, VerifiedGovernance, VerifiedGroup, GOVERNANCE_FIELDS,
};
pub use governance_binding::{
    governance_model_binding_authorized_from_env, governance_model_binding_matches,
    governance_model_file_matches, EXPECTED_GOVERNANCE_MODEL_SHA256_ENV,
};
pub use governed_input::{
    parse_governed_object_request, AcceptedGovernedRequest, ContractPermission,
    GovernedInputConfig, UserMessage, GOVERNED_REQUEST_PROTOCOL,
};
pub use model_phase::Phase;
pub use model_protocol::{
    NativeToolResult, ParsedToolCall, MODEL_REQUEST_DIGEST_DOMAIN, RENDERED_PROMPT_DIGEST_DOMAIN,
};
pub use runnable_manifest::{RUNNABLE_TASK_DIGEST_DOMAIN, RUNNABLE_TASK_SCHEMA};
pub use runtime::GovernedRuntime;
pub use sensitive_trace::{
    BuildMetadata, SensitiveTrace, SensitiveTraceEvent, SensitiveTraceKind, SensitiveTraceSink,
    SENSITIVE_TRACE_SCHEMA,
};
pub use session::{ModelTurn, Session, State, TurnPermit};
pub use tools::{RegisteredCall, RegisteredToolSpec, ToolDispatcher};

pub use execution_binding::{
    ExecutionBackend, ExecutionIdentity, VllmBackend, VllmExecutionIdentity, SAMPLING_FIELDS,
    VLLM_REVISION,
};
