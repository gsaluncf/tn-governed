use std::io;
use std::path::Path;
use std::sync::Arc;

use uuid::Uuid;

use crate::admission::AdmissionController;
use crate::audit::{AuditEvent, AuditFacts, AuditLog, DecisionAudit};
use crate::config::{output_state_is_separate, RequestLimits, RuntimeConfig};
use crate::contract::ReportContract;
use crate::governed_input::{parse_governed_object_request, GovernedInputRuntime};
use crate::model_protocol::session_error;
use crate::output_tn::GovernedOutputPublisher;
use crate::sensitive_trace::{
    BuildMetadata, SensitiveTrace, SensitiveTraceEvent, SensitiveTraceKind, SensitiveTraceSink,
};
use crate::session::Session;
use crate::tools::ToolDispatcher;
use crate::TnLlamaError;

#[derive(Clone)]
pub struct GovernedRuntime {
    pub(crate) inner: Arc<RuntimeInner>,
}

pub(crate) struct RuntimeInner {
    pub(crate) execution_backend: crate::ExecutionBackend,
    pub(crate) run_id: String,
    pub(crate) limits: RequestLimits,
    pub(crate) admission: AdmissionController,
    pub(crate) audit: Arc<dyn DecisionAudit>,
    pub(crate) trace: Arc<dyn SensitiveTraceSink>,
    pub(crate) report_contract: Arc<ReportContract>,
    pub(crate) governed_input: Arc<GovernedInputRuntime>,
    pub(crate) governed_output: Arc<GovernedOutputPublisher>,
    pub(crate) tool_dispatcher: Arc<ToolDispatcher>,
    pub(crate) final_max_tokens: u32,
}

impl GovernedRuntime {
    pub fn from_config_with_backend(
        config: RuntimeConfig,
        backend: crate::ExecutionBackend,
    ) -> Result<Self, TnLlamaError> {
        validate_config(&config, &backend)?;
        let audit_path = config.audit_path.clone();
        let trace_dir = config.raw_trace_dir.clone();
        let metadata = BuildMetadata::from(&config);
        Self::from_config_with_backend_and_sinks(
            config,
            backend,
            move |run_id| {
                AuditLog::create(&audit_path, run_id)
                    .map(|sink| Arc::new(sink) as Arc<dyn DecisionAudit>)
            },
            move |run_id| {
                SensitiveTrace::create(&trace_dir, run_id, metadata.clone())
                    .map(|sink| Arc::new(sink) as Arc<dyn SensitiveTraceSink>)
            },
        )
    }

    pub fn from_config(config: RuntimeConfig) -> Result<Self, TnLlamaError> {
        Self::from_config_with_backend(config, crate::ExecutionBackend::Llama)
    }

    #[doc(hidden)]
    pub fn from_config_with_sink_factories<A, T>(
        config: RuntimeConfig,
        audit_factory: A,
        trace_factory: T,
    ) -> Result<Self, TnLlamaError>
    where
        A: Fn(&str) -> io::Result<Arc<dyn DecisionAudit>> + Send + Sync + 'static,
        T: Fn(&str) -> io::Result<Arc<dyn SensitiveTraceSink>> + Send + Sync + 'static,
    {
        Self::from_config_with_backend_and_sinks(
            config,
            crate::ExecutionBackend::Llama,
            audit_factory,
            trace_factory,
        )
    }

    fn from_config_with_backend_and_sinks<A, T>(
        config: RuntimeConfig,
        backend: crate::ExecutionBackend,
        audit_factory: A,
        trace_factory: T,
    ) -> Result<Self, TnLlamaError>
    where
        A: Fn(&str) -> io::Result<Arc<dyn DecisionAudit>> + Send + Sync + 'static,
        T: Fn(&str) -> io::Result<Arc<dyn SensitiveTraceSink>> + Send + Sync + 'static,
    {
        validate_config(&config, &backend)?;
        let limits = RequestLimits {
            max_request_bytes: config.max_request_bytes,
            max_message_bytes: config.max_message_bytes,
            expected_event_type: config.expected_event_type.clone(),
            allowed_input_groups: config.allowed_input_groups.clone(),
        };
        let report_contract = Arc::new(config.report_contract.clone());
        let governed_output = Arc::new(GovernedOutputPublisher::from_config(&config)?);
        let tool_dispatcher = configured_tools(&report_contract, &governed_output)?;
        let profile = config.governed_objects.clone().ok_or_else(|| {
            session_error(
                "tn_session_state",
                "runtime configuration lacks the governed object profile",
            )
        })?;
        let governed_input = Arc::new(GovernedInputRuntime::load(profile)?);
        let run_id = Uuid::now_v7().to_string();
        let audit = audit_factory(&run_id).map_err(|_| {
            session_error(
                "tn_audit_append_failed",
                "decision audit sink could not be created",
            )
        })?;
        let trace = trace_factory(&run_id).map_err(|_| {
            session_error(
                "tn_sensitive_trace_append_failed",
                "sensitive trace sink could not be created",
            )
        })?;
        Ok(Self {
            inner: Arc::new(RuntimeInner {
                execution_backend: backend,
                run_id,
                limits,
                admission: AdmissionController::new(config.max_active_sessions),
                audit,
                trace,
                report_contract,
                governed_input,
                governed_output,
                tool_dispatcher: Arc::new(tool_dispatcher),
                final_max_tokens: config.final_max_tokens,
            }),
        })
    }

    pub fn start_session(&self, raw: &[u8]) -> Result<Session, TnLlamaError> {
        let run_id = &self.inner.run_id;
        let reservation_id = match self.inner.execution_backend {
            crate::ExecutionBackend::Llama => run_id.clone(),
            crate::ExecutionBackend::Vllm(_) => Uuid::now_v7().to_string(),
        };
        let audit = Arc::clone(&self.inner.audit);
        let trace = Arc::clone(&self.inner.trace);
        if trace
            .append(SensitiveTraceEvent {
                run_id,
                phase: None,
                kind: SensitiveTraceKind::Ingress,
                task_id: None,
                slot_id: None,
                request_json: Some(raw),
                rendered_prompt: None,
                runnable_manifest: None,
                raw_model_output: None,
                parsed_content: None,
                error_code: None,
            })
            .is_err()
        {
            return Err(session_error(
                "tn_sensitive_trace_append_failed",
                "request ingress trace append failed",
            ));
        }
        let input = &self.inner.governed_input;
        let accepted = match parse_governed_object_request(raw, &self.inner.limits, &input.config) {
            Ok(value) => value,
            Err(error) => {
                append_runtime_terminal_audit(audit.as_ref(), "received", "", "", error.code())
                    .map_err(|_| {
                        session_error(
                            "tn_audit_append_failed",
                            "request rejection audit append failed",
                        )
                    })?;
                return Err(error);
            }
        };
        let object_id = accepted.object.id().to_owned();
        let request_digest = accepted.request_digest.clone();
        let admitted = match self
            .inner
            .admission
            .admit_governed(accepted, &reservation_id)
        {
            Ok(admitted) => admitted,
            Err(error) => {
                append_runtime_terminal_audit(
                    audit.as_ref(),
                    "received",
                    &object_id,
                    &request_digest,
                    error.code(),
                )
                .map_err(|_| {
                    session_error(
                        "tn_audit_append_failed",
                        "standalone refusal audit append failed",
                    )
                })?;
                return Err(error);
            }
        };
        append_runtime_audit(
            audit.as_ref(),
            "standalone_object_reserved",
            "received",
            "governance_admission",
            &object_id,
            &request_digest,
            AuditFacts {
                hashes_verified: Some(true),
                signature_verified: Some(true),
                ..AuditFacts::default()
            },
        )
        .map_err(|_| {
            session_error(
                "tn_audit_append_failed",
                "object admission audit append failed",
            )
        })?;
        Session::new(
            run_id.clone(),
            self.inner.execution_backend.clone(),
            admitted,
            audit,
            trace,
            Arc::clone(&self.inner.report_contract),
            Arc::clone(&self.inner.tool_dispatcher),
            self.inner.final_max_tokens,
            crate::session::GovernedSessionState {
                input: Arc::clone(input),
                output: Arc::clone(&self.inner.governed_output),
                view: None,
                route: None,
                data: None,
                tools: Vec::new(),
                context: None,
            },
        )
    }
}

fn validate_config(
    config: &RuntimeConfig,
    backend: &crate::ExecutionBackend,
) -> Result<(), TnLlamaError> {
    let absolute_paths = [
        config.input_index_key_path.as_path(),
        config.output_tn_config_path.as_path(),
        config.output_reader_key_dir.as_path(),
        config.output_index_key_path.as_path(),
        config.audit_path.as_path(),
        config.raw_trace_dir.as_path(),
    ];
    let valid = config.version == "tn.llama.runtime.v2"
        && nonempty(&config.expected_event_type)
        && config.writer_authority == "group_capability"
        && valid_report_contract(config)
        && nonempty(&config.output_ceremony_id)
        && config.output_governance_group == "tn.agents"
        && config.input_index_epoch == 0
        && config.output_index_epoch == 0
        && output_state_is_separate(config)
        && absolute_paths.iter().all(|path| Path::is_absolute(path))
        && config.max_request_bytes > 0
        && config.max_message_bytes > 0
        && match backend {
            crate::ExecutionBackend::Llama => config.max_active_sessions == 1,
            crate::ExecutionBackend::Vllm(_) => config.max_active_sessions > 0,
        }
        && config.final_max_tokens > 0;
    if valid {
        Ok(())
    } else {
        Err(session_error(
            "tn_session_state",
            "runtime configuration does not match the fixed encrypted profile",
        ))
    }
}

fn valid_report_contract(config: &RuntimeConfig) -> bool {
    let contract = &config.report_contract;
    config.governed_objects.as_ref().is_some_and(|profile| {
        contract.operation == profile.use_context.operation()
            && contract
                .section_rules
                .values()
                .all(|rule| rule.propagate_source_governance)
    }) && contract.output_public_section == "default"
        && !config.allowed_input_groups.is_empty()
        && config.allowed_input_groups.iter().all(|name| {
            nonempty(name)
                && !tn_core::sealed_object::ENVELOPE_RESERVED.contains(&name.as_str())
                && name != "tn_aad"
                && name != "tn.agents"
        })
        && !contract.allowed_input_sections.is_empty()
        && contract
            .allowed_input_sections
            .iter()
            .all(|name| config.allowed_input_groups.contains(name))
        && contract
            .section_rules
            .keys()
            .all(|name| contract.allowed_input_sections.contains(name))
        && contract.section_rules.values().all(|rule| {
            rule.required_attribution
                .as_ref()
                .is_none_or(|value| nonempty(value))
                && rule
                    .required_tool
                    .as_ref()
                    .is_none_or(|value| nonempty(value))
        })
        && nonempty(&contract.output_event_type)
        && nonempty(&contract.output_public_section)
        && nonempty(&contract.operation)
        && [
            &contract.output_policy.instruction,
            &contract.output_policy.use_for,
            &contract.output_policy.do_not_use_for,
            &contract.output_policy.consequences,
            &contract.output_policy.on_violation_or_error,
        ]
        .into_iter()
        .all(|value| nonempty(value))
}

/// The one protected tool the report contract names, published through the governed output.
fn configured_tools(
    contract: &ReportContract,
    publisher: &Arc<GovernedOutputPublisher>,
) -> Result<ToolDispatcher, TnLlamaError> {
    let configured = contract
        .section_rules
        .values()
        .filter_map(|rule| rule.required_tool.as_ref())
        .collect::<std::collections::BTreeSet<_>>();
    match configured.len() {
        0 => Ok(ToolDispatcher::empty()),
        1 => ToolDispatcher::native(
            Arc::clone(publisher),
            configured.first().expect("one configured tool"),
        ),
        _ => Err(session_error(
            "tn_tool_registration_invalid",
            "runtime config names more governed tools than this registry provides",
        )),
    }
}

fn nonempty(value: &str) -> bool {
    !value.trim().is_empty()
}

fn append_runtime_audit(
    audit: &dyn DecisionAudit,
    kind: &str,
    state_before: &str,
    state_after: &str,
    row_hash: &str,
    request_digest: &str,
    facts: AuditFacts,
) -> io::Result<()> {
    let mut event = AuditEvent::transition(state_before, state_after, row_hash, "allow");
    event.kind = kind.to_string();
    event.request_digest = request_digest.to_string();
    event.facts = facts;
    audit.append(event).map(|_| ())
}

fn append_runtime_terminal_audit(
    audit: &dyn DecisionAudit,
    state_before: &str,
    row_hash: &str,
    request_digest: &str,
    error_code: &str,
) -> io::Result<()> {
    let mut event = AuditEvent::transition(state_before, "failed", row_hash, "deny");
    event.kind = "terminal_error".to_string();
    event.request_digest = request_digest.to_string();
    event.error_code = Some(error_code.to_string());
    audit.append(event).map(|_| ())
}
