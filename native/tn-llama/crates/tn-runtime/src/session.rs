use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use serde_json::{Map, Value};

use crate::admission::{AdmittedInput, AdmittedRequest};
use crate::audit::{AuditDigest, AuditEvent, AuditFacts, DecisionAudit};
use crate::client_trace::{ActionOutcome, ClientTraceEvent, ReportRelease, RELEASE_PROTOCOL};
use crate::contract::ReportContract;
use crate::governance::{GovernanceReader, VerifiedGovernance};
use crate::model_phase::Phase;
use crate::model_protocol::{
    decrypt_turn_body, governance_context_digest, governed_action_body, model_request_digest,
    rendered_prompt_digest, section_selection_body, session_error, AcceptedCall,
    GovernedActionBodyInput, NativeToolResult, ToolExchange,
};
use crate::output_tn::{
    ComplianceReceipt, OutputPublisher, ReportProposal, SourceLineage, TrustedDerivation,
};
use crate::sensitive_trace::{SensitiveTraceEvent, SensitiveTraceKind, SensitiveTraceSink};
use crate::tools::{RegisteredCall, ToolContext, ToolDispatcher, ToolReceipt};
use crate::TnLlamaError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    GovernanceAdmission,
    SectionSelection,
    GovernedAction,
    Complete,
    Failed,
}

impl State {
    const fn phase(self) -> Option<Phase> {
        match self {
            Self::GovernanceAdmission => None,
            Self::SectionSelection => Some(Phase::SectionSelection),
            Self::GovernedAction => Some(Phase::GovernedAction),
            Self::Complete | Self::Failed => None,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::GovernanceAdmission => "governance_admission",
            Self::SectionSelection => "section_selection",
            Self::GovernedAction => "governed_action",
            Self::Complete => "complete",
            Self::Failed => "failed",
        }
    }
}

pub struct ModelTurn {
    pub permit: TurnPermit,
    pub request_json: Vec<u8>,
    pub model_request_digest: String,
}

impl fmt::Debug for ModelTurn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModelTurn")
            .field("phase", &self.permit.phase)
            .field("model_request_digest", &self.model_request_digest)
            .finish_non_exhaustive()
    }
}

pub struct Session {
    core: Arc<Mutex<SessionCore>>,
}

impl fmt::Debug for Session {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Session")
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

struct SessionCore {
    execution_backend: crate::ExecutionBackend,
    run_id: String,
    row_hash: String,
    request_digest: String,
    user_content: String,
    state: State,
    admitted: Option<AdmittedInput>,
    governed: Option<GovernedSessionState>,
    governance_reader: Arc<GovernanceReader>,
    report_contract: Arc<ReportContract>,
    output_publisher: Option<Arc<OutputPublisher>>,
    tool_dispatcher: Arc<ToolDispatcher>,
    audit: Arc<dyn DecisionAudit>,
    trace: Arc<dyn SensitiveTraceSink>,
    final_max_tokens: u32,
    next_turn_serial: u64,
    outstanding: Option<OutstandingTurn>,
    governance: Option<VerifiedGovernance>,
    selected_sections: BTreeSet<String>,
    opened_sections: BTreeMap<String, Value>,
    selection_call: Option<StoredCall>,
    governed_tool_exchanges: Vec<StoredToolExchange>,
    compliance_receipt: Option<ComplianceReceipt>,
    client_trace: Vec<ClientTraceEvent>,
}

pub(crate) struct GovernedSessionState {
    pub input: Arc<crate::governed_input::GovernedInputRuntime>,
    pub output: Arc<crate::output_tn::GovernedOutputPublisher>,
    pub view: Option<tn_core::governed::GovernanceView>,
    pub data: Option<tn_core::governed::DataObject>,
    pub tools: Vec<crate::output_tn::GovernedPublication>,
    /// The decision context computed for these tool objects.
    pub context: Option<(Vec<String>, BTreeMap<String, Value>)>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CallOrigin {
    Model,
    Runtime,
}

struct StoredCall {
    origin: CallOrigin,
    id: String,
    name: String,
    arguments: String,
}

struct StoredToolExchange {
    call: StoredCall,
    result: String,
}

struct OutstandingTurn {
    execution_identity: Option<crate::ExecutionIdentity>,
    serial: u64,
    phase: Phase,
    request_json: Vec<u8>,
    model_request_digest: String,
    context_digest: String,
    n_predict: u32,
    lifecycle: PermitLifecycle,
    rendered_prompt_digest: Option<String>,
    runnable_task_digest: Option<String>,
    task_id: Option<i64>,
    slot_id: Option<i32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PermitLifecycle {
    Issued,
    Prepared,
    Begun,
    Consumed,
    Invalid,
}

pub struct TurnPermit {
    core: Arc<Mutex<SessionCore>>,
    run_id: String,
    serial: u64,
    phase: Phase,
}

impl fmt::Debug for TurnPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TurnPermit")
            .field("run_id", &self.run_id)
            .field("serial", &self.serial)
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

impl TurnPermit {
    #[must_use]
    pub const fn phase(&self) -> Phase {
        self.phase
    }

    pub fn prepare(
        &self,
        request_json: &[u8],
        rendered_prompt: &[u8],
        runnable_manifest: &[u8],
    ) -> Result<(), TnLlamaError> {
        let mut core = lock_core(&self.core)?;
        let validation = (|| {
            validate_identity(&core, self)?;
            let outstanding = core.outstanding.as_ref().ok_or_else(|| {
                session_error("tn_turn_consumed", "turn permit is no longer outstanding")
            })?;
            match outstanding.lifecycle {
                PermitLifecycle::Issued => {}
                PermitLifecycle::Prepared => {
                    return Err(session_error(
                        "tn_turn_already_prepared",
                        "turn permit was already prepared",
                    ));
                }
                PermitLifecycle::Begun => {
                    return Err(session_error(
                        "tn_turn_already_begun",
                        "turn permit was already begun",
                    ));
                }
                PermitLifecycle::Consumed => {
                    return Err(session_error(
                        "tn_turn_consumed",
                        "turn permit was already consumed",
                    ));
                }
                PermitLifecycle::Invalid => {
                    return Err(session_error("tn_session_state", "turn permit is invalid"));
                }
            }
            if request_json != outstanding.request_json {
                return Err(session_error(
                    "tn_turn_binding_mismatch",
                    "prepared model body differs from the Rust-issued bytes",
                ));
            }
            let manifest_digest = core.execution_backend.digest(
                runnable_manifest,
                self.phase,
                outstanding.n_predict,
            )?;
            Ok((rendered_prompt_digest(rendered_prompt), manifest_digest))
        })();
        let (prompt_digest, manifest_digest) = match validation {
            Ok(digests) => digests,
            Err(error) => return Err(terminalize(&mut core, error, FailedSink::None)),
        };
        if core
            .trace
            .append(SensitiveTraceEvent {
                run_id: &core.run_id,
                phase: Some(self.phase),
                kind: SensitiveTraceKind::TurnPrepared,
                task_id: None,
                slot_id: None,
                request_json: Some(request_json),
                rendered_prompt: Some(rendered_prompt),
                runnable_manifest: Some(runnable_manifest),
                raw_model_output: None,
                parsed_content: None,
                error_code: None,
            })
            .is_err()
        {
            return Err(terminalize(
                &mut core,
                session_error(
                    "tn_sensitive_trace_append_failed",
                    "turn preparation trace append failed",
                ),
                FailedSink::Trace,
            ));
        }
        let outstanding = core.outstanding.as_mut().expect("validated outstanding");
        outstanding.rendered_prompt_digest = Some(prompt_digest);
        outstanding.runnable_task_digest = Some(manifest_digest);
        outstanding.lifecycle = PermitLifecycle::Prepared;
        Ok(())
    }

    pub fn begin(
        &self,
        task_id: i64,
        slot_id: i32,
        request_json: &[u8],
        rendered_prompt: &[u8],
        runnable_manifest: &[u8],
    ) -> Result<(), TnLlamaError> {
        self.begin_execution(
            crate::ExecutionIdentity::Llama { task_id, slot_id },
            request_json,
            rendered_prompt,
            runnable_manifest,
        )
    }

    pub fn begin_vllm(
        &self,
        identity: crate::VllmExecutionIdentity,
        request_json: &[u8],
        rendered_prompt: &[u8],
        runnable_manifest: &[u8],
    ) -> Result<(), TnLlamaError> {
        self.begin_execution(
            crate::ExecutionIdentity::Vllm(identity),
            request_json,
            rendered_prompt,
            runnable_manifest,
        )
    }

    fn begin_execution(
        &self,
        identity: crate::ExecutionIdentity,
        request_json: &[u8],
        rendered_prompt: &[u8],
        runnable_manifest: &[u8],
    ) -> Result<(), TnLlamaError> {
        let (task_id, slot_id) = match &identity {
            crate::ExecutionIdentity::Llama { task_id, slot_id } => {
                (Some(*task_id), Some(*slot_id))
            }
            crate::ExecutionIdentity::Vllm(_) => (None, None),
        };
        let mut core = lock_core(&self.core)?;
        let validation = (|| {
            validate_identity(&core, self)?;
            core.execution_backend
                .validate_identity(&identity, runnable_manifest)?;
            let outstanding = core.outstanding.as_ref().ok_or_else(|| {
                session_error("tn_turn_consumed", "turn permit is no longer outstanding")
            })?;
            match outstanding.lifecycle {
                PermitLifecycle::Issued => {
                    return Err(session_error(
                        "tn_turn_not_prepared",
                        "turn permit must be prepared before begin",
                    ));
                }
                PermitLifecycle::Prepared => {}
                PermitLifecycle::Begun => {
                    return Err(session_error(
                        "tn_turn_already_begun",
                        "turn permit was already begun",
                    ));
                }
                PermitLifecycle::Consumed => {
                    return Err(session_error(
                        "tn_turn_consumed",
                        "turn permit was already consumed",
                    ));
                }
                PermitLifecycle::Invalid => {
                    return Err(session_error("tn_session_state", "turn permit is invalid"));
                }
            }
            if request_json != outstanding.request_json {
                return Err(session_error(
                    "tn_turn_binding_mismatch",
                    "begun model body differs from the prepared bytes",
                ));
            }
            let prompt_digest = rendered_prompt_digest(rendered_prompt);
            let manifest_digest = core.execution_backend.digest(
                runnable_manifest,
                self.phase,
                outstanding.n_predict,
            )?;
            if outstanding.rendered_prompt_digest.as_deref() != Some(&prompt_digest)
                || outstanding.runnable_task_digest.as_deref() != Some(&manifest_digest)
            {
                return Err(session_error(
                    "tn_turn_binding_mismatch",
                    "begun task does not match the prepared body, prompt, and manifest",
                ));
            }
            Ok(())
        })();
        if let Err(error) = validation {
            return Err(terminalize(&mut core, error, FailedSink::None));
        }
        if core
            .trace
            .append(SensitiveTraceEvent {
                run_id: &core.run_id,
                phase: Some(self.phase),
                kind: SensitiveTraceKind::TurnStarted,
                task_id: task_id,
                slot_id: slot_id,
                request_json: Some(request_json),
                rendered_prompt: Some(rendered_prompt),
                runnable_manifest: Some(runnable_manifest),
                raw_model_output: None,
                parsed_content: None,
                error_code: None,
            })
            .is_err()
        {
            return Err(terminalize(
                &mut core,
                session_error(
                    "tn_sensitive_trace_append_failed",
                    "turn begin trace append failed",
                ),
                FailedSink::Trace,
            ));
        }
        let mut context_facts = governance_identity_facts(&core);
        context_facts.context_digest = Some(audit_digest(
            &core
                .outstanding
                .as_ref()
                .expect("validated outstanding")
                .context_digest,
        ));
        context_facts.execution_identity = match &identity {
            crate::ExecutionIdentity::Vllm(_) => Some(identity.clone()),
            _ => None,
        };
        if append_audit(
            &core,
            "governance_context_bound",
            core.state,
            core.state,
            Some(self.phase),
            task_id,
            slot_id,
            "allow",
            None,
            context_facts,
        )
        .is_err()
        {
            return Err(terminalize(
                &mut core,
                session_error(
                    "tn_audit_append_failed",
                    "governance context binding audit append failed",
                ),
                FailedSink::Audit,
            ));
        }
        if append_audit(
            &core,
            "turn_begin_authorized",
            core.state,
            core.state,
            Some(self.phase),
            task_id,
            slot_id,
            "allow",
            None,
            AuditFacts {
                execution_identity: match &identity {
                    crate::ExecutionIdentity::Vllm(_) => Some(identity.clone()),
                    _ => None,
                },
                ..AuditFacts::default()
            },
        )
        .is_err()
        {
            return Err(terminalize(
                &mut core,
                session_error(
                    "tn_audit_append_failed",
                    "turn begin authorization audit append failed",
                ),
                FailedSink::Audit,
            ));
        }
        let outstanding = core.outstanding.as_mut().expect("validated outstanding");
        outstanding.execution_identity = Some(identity);
        outstanding.task_id = task_id;
        outstanding.slot_id = slot_id;
        outstanding.lifecycle = PermitLifecycle::Begun;
        Ok(())
    }
}

impl Session {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        run_id: String,
        execution_backend: crate::ExecutionBackend,
        admitted: AdmittedInput,
        governance_reader: Arc<GovernanceReader>,
        audit: Arc<dyn DecisionAudit>,
        trace: Arc<dyn SensitiveTraceSink>,
        report_contract: Arc<ReportContract>,
        output_publisher: Option<Arc<OutputPublisher>>,
        tool_dispatcher: Arc<ToolDispatcher>,
        final_max_tokens: u32,
        governed: Option<GovernedSessionState>,
    ) -> Result<Self, TnLlamaError> {
        let (row_hash, request_digest, user_content, source_id) = match &admitted {
            AdmittedInput::LegacyChained(input) => (
                input.request.row.row_hash().to_string(),
                input.request.request_digest.clone(),
                input.request.messages[0].content.clone(),
                input.request.row.event_id().to_string(),
            ),
            AdmittedInput::GovernedObject(input) => (
                input.request.object.id().to_string(),
                input.request.request_digest.clone(),
                input.request.messages[0].content.clone(),
                input.request.object.id().to_string(),
            ),
        };
        let client_trace = vec![ClientTraceEvent {
            ordinal: 1,
            event: "admission".to_string(),
            state: "governance_admission".to_string(),
            task_id: None,
            slot_id: None,
            row_hash: Some(row_hash.clone()),
            selected_sections: Vec::new(),
            tool_name: None,
            event_id: Some(source_id),
        }];
        let session = Self {
            core: Arc::new(Mutex::new(SessionCore {
                execution_backend,
                run_id,
                row_hash,
                request_digest,
                user_content,
                state: State::GovernanceAdmission,
                admitted: Some(admitted),
                governed,
                governance_reader,
                report_contract,
                output_publisher,
                tool_dispatcher,
                audit,
                trace,
                final_max_tokens,
                next_turn_serial: 0,
                outstanding: None,
                governance: None,
                selected_sections: BTreeSet::new(),
                opened_sections: BTreeMap::new(),
                selection_call: None,
                governed_tool_exchanges: Vec::new(),
                compliance_receipt: None,
                client_trace,
            })),
        };
        {
            let mut core = lock_core(&session.core)?;
            admit_governance(&mut core)?;
        }
        Ok(session)
    }

    #[must_use]
    pub fn state(&self) -> State {
        lock_recover(&self.core).state
    }

    pub fn next_model_turn(&mut self) -> Result<ModelTurn, TnLlamaError> {
        let mut core = lock_core(&self.core)?;
        if core.outstanding.is_some() {
            return Err(terminalize(
                &mut core,
                session_error(
                    "tn_turn_outstanding",
                    "the current phase already has an outstanding permit",
                ),
                FailedSink::None,
            ));
        }
        advance_runtime_actions(&mut core)?;
        let phase = match core.state.phase() {
            Some(phase) => phase,
            None => {
                return Err(session_error(
                    "tn_session_state",
                    "terminal session cannot issue a model turn",
                ));
            }
        };
        let governance_context = match model_governance(&mut core) {
            Ok(context) => context,
            Err(error) => return Err(terminalize(&mut core, error, FailedSink::None)),
        };
        let request_json = (|| -> Result<Vec<u8>, TnLlamaError> {
            match phase {
                Phase::GovernanceRead | Phase::CommitmentEcho => Err(session_error(
                    "tn_turn_phase_mismatch",
                    "reserved model phase cannot issue a turn",
                )),
                Phase::SectionSelection if core.governed.is_some() => {
                    let (governance_hash, encrypted_data) = governed_hash_keys(&core)?;
                    decrypt_turn_body(
                        &core.user_content,
                        &encrypted_data,
                        &governance_hash,
                        &governance_context,
                        core.final_max_tokens,
                    )
                }
                Phase::SectionSelection => {
                    let available_sections = available_section_manifest(&core)?;
                    section_selection_body(
                        &core.user_content,
                        &available_sections,
                        &governance_context,
                        core.final_max_tokens,
                    )
                }
                Phase::GovernedAction => governed_action_request(&core, &governance_context),
            }
        })();
        let request_json = match request_json {
            Ok(body) => body,
            Err(error) => return Err(terminalize(&mut core, error, FailedSink::None)),
        };
        let digest = model_request_digest(&request_json);
        core.next_turn_serial += 1;
        let serial = core.next_turn_serial;
        let n_predict = core.final_max_tokens;
        let context_digest = match governance_context_digest(&governance_context) {
            Ok(digest) => digest,
            Err(error) => return Err(terminalize(&mut core, error, FailedSink::None)),
        };
        core.outstanding = Some(OutstandingTurn {
            execution_identity: None,
            serial,
            phase,
            request_json: request_json.clone(),
            model_request_digest: digest.clone(),
            context_digest,
            n_predict,
            lifecycle: PermitLifecycle::Issued,
            rendered_prompt_digest: None,
            runnable_task_digest: None,
            task_id: None,
            slot_id: None,
        });
        Ok(ModelTurn {
            permit: TurnPermit {
                core: Arc::clone(&self.core),
                run_id: core.run_id.clone(),
                serial,
                phase,
            },
            request_json,
            model_request_digest: digest,
        })
    }

    pub fn accept_model_action(
        &mut self,
        permit: TurnPermit,
        result: NativeToolResult<'_>,
    ) -> Result<ActionOutcome, TnLlamaError> {
        match permit.phase {
            Phase::GovernanceRead | Phase::CommitmentEcho => Err(session_error(
                "tn_turn_phase_mismatch",
                "reserved model phase cannot accept a result",
            )),
            Phase::SectionSelection => self.accept_section_selection(permit, result),
            Phase::GovernedAction => self.accept_governed_action(permit, result),
        }
    }

    fn accept_section_selection(
        &mut self,
        permit: TurnPermit,
        result: NativeToolResult<'_>,
    ) -> Result<ActionOutcome, TnLlamaError> {
        if !Arc::ptr_eq(&self.core, &permit.core) {
            let mut core = lock_core(&self.core)?;
            return Err(terminalize(
                &mut core,
                session_error(
                    "tn_turn_session_mismatch",
                    "turn permit belongs to a different session",
                ),
                FailedSink::None,
            ));
        }
        let mut core = lock_core(&self.core)?;
        if let Err(error) = validate_begun(&core, &permit) {
            return Err(terminalize(&mut core, error, FailedSink::None));
        }
        if core
            .trace
            .append(SensitiveTraceEvent {
                run_id: &core.run_id,
                phase: Some(permit.phase),
                kind: SensitiveTraceKind::ModelResult,
                task_id: core.outstanding.as_ref().and_then(|turn| turn.task_id),
                slot_id: core.outstanding.as_ref().and_then(|turn| turn.slot_id),
                request_json: None,
                rendered_prompt: None,
                runnable_manifest: None,
                raw_model_output: Some(result.raw_model_output),
                parsed_content: Some(result.content),
                error_code: None,
            })
            .is_err()
        {
            return Err(terminalize(
                &mut core,
                session_error(
                    "tn_sensitive_trace_append_failed",
                    "model-result trace append failed",
                ),
                FailedSink::Trace,
            ));
        }
        let call = match validate_native_call(&core, permit.phase, &result) {
            Ok(call) => call,
            Err(error) => return Err(terminalize(&mut core, error, FailedSink::None)),
        };
        let arguments = crate::envelope::parse_duplicate_safe_json(call.arguments.as_bytes())
            .expect("native call arguments were validated");
        let selected_sections = match selection_arguments(&core, &arguments) {
            Ok(sections) => sections,
            Err(error) => return Err(terminalize(&mut core, error, FailedSink::None)),
        };
        let outcome =
            apply_section_selection(&mut core, Some(permit.phase), call, selected_sections)?;
        retain_presented_fields(&mut core, &arguments);
        Ok(outcome)
    }

    fn accept_governed_action(
        &mut self,
        permit: TurnPermit,
        result: NativeToolResult<'_>,
    ) -> Result<ActionOutcome, TnLlamaError> {
        if !Arc::ptr_eq(&self.core, &permit.core) {
            let mut core = lock_core(&self.core)?;
            return Err(terminalize(
                &mut core,
                session_error(
                    "tn_turn_session_mismatch",
                    "turn permit belongs to a different session",
                ),
                FailedSink::None,
            ));
        }
        let mut core = lock_core(&self.core)?;
        if let Err(error) = validate_begun(&core, &permit) {
            return Err(terminalize(&mut core, error, FailedSink::None));
        }
        if core
            .trace
            .append(SensitiveTraceEvent {
                run_id: &core.run_id,
                phase: Some(permit.phase),
                kind: SensitiveTraceKind::ModelResult,
                task_id: core.outstanding.as_ref().and_then(|turn| turn.task_id),
                slot_id: core.outstanding.as_ref().and_then(|turn| turn.slot_id),
                request_json: None,
                rendered_prompt: None,
                runnable_manifest: None,
                raw_model_output: Some(result.raw_model_output),
                parsed_content: Some(result.content),
                error_code: None,
            })
            .is_err()
        {
            return Err(terminalize(
                &mut core,
                session_error(
                    "tn_sensitive_trace_append_failed",
                    "model-result trace append failed",
                ),
                FailedSink::Trace,
            ));
        }
        let call = match validate_native_call(&core, permit.phase, &result) {
            Ok(call) => call,
            Err(error) => return Err(terminalize(&mut core, error, FailedSink::None)),
        };
        accept_action(&mut core, Some(permit.phase), call)
    }

    pub fn abort(&mut self) -> Result<(), TnLlamaError> {
        let mut core = lock_core(&self.core)?;
        if matches!(core.state, State::Complete | State::Failed) {
            return Err(session_error(
                "tn_session_state",
                "terminal session cannot be aborted again",
            ));
        }
        core.state = State::Failed;
        if let Some(outstanding) = core.outstanding.as_mut() {
            outstanding.lifecycle = PermitLifecycle::Invalid;
        }
        core.outstanding = None;
        if let Some(admitted) = core.admitted.take() {
            admitted.abort()?;
        }
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let mut core = lock_recover(&self.core);
        if let Some(admitted) = core.admitted.take() {
            let _ = admitted.abort();
        }
        if !matches!(core.state, State::Complete) {
            core.state = State::Failed;
        }
    }
}

fn apply_section_selection(
    core: &mut SessionCore,
    phase: Option<Phase>,
    call: StoredCall,
    selected_sections: BTreeSet<String>,
) -> Result<ActionOutcome, TnLlamaError> {
    let mut opened_sections = BTreeMap::new();
    if let Some(state) = &core.governed {
        let data = match state.input.open(
            core.governed_request(),
            state.view.as_ref().expect("governance accepted"),
            &selected_sections,
        ) {
            Ok(data) => data,
            Err(error) => return Err(terminalize(core, error, FailedSink::None)),
        };
        opened_sections = data
            .groups()
            .iter()
            .map(|(name, fields)| (name.clone(), Value::Object(fields.clone())))
            .collect();
        core.governed.as_mut().expect("governed state").data = Some(data);
    } else {
        for section in &selected_sections {
            let opened = match core
                .governance_reader
                .open_group_and_verify(&core.admitted_request().request.row, section)
            {
                Ok(opened) => opened,
                Err(error) => return Err(terminalize(core, error, FailedSink::None)),
            };
            opened_sections.insert(
                section.clone(),
                Value::Object(opened.plaintext.into_iter().collect()),
            );
        }
    }
    if append_audit(
        core,
        if call.origin == CallOrigin::Runtime {
            "sections_selected_runtime"
        } else {
            "sections_selected"
        },
        State::SectionSelection,
        State::GovernedAction,
        phase,
        core.outstanding.as_ref().and_then(|turn| turn.task_id),
        core.outstanding.as_ref().and_then(|turn| turn.slot_id),
        "allow",
        None,
        AuditFacts {
            incomplete: Some(false),
            ..AuditFacts::default()
        },
    )
    .is_err()
    {
        return Err(terminalize(
            core,
            session_error(
                "tn_audit_append_failed",
                "section-selection audit append failed",
            ),
            FailedSink::Audit,
        ));
    }
    let task_id = core.outstanding.as_ref().and_then(|turn| turn.task_id);
    let slot_id = core.outstanding.as_ref().and_then(|turn| turn.slot_id);
    let trace_row_hash = core.row_hash.clone();
    consume_outstanding(core);
    core.selected_sections = selected_sections;
    core.opened_sections = opened_sections;
    let runtime_selected = call.origin == CallOrigin::Runtime;
    core.selection_call = Some(call);
    core.state = State::GovernedAction;
    push_client_trace(
        core,
        if runtime_selected {
            "sections_selected_runtime"
        } else {
            "sections_selected"
        },
        State::GovernedAction,
        task_id,
        slot_id,
        Some(trace_row_hash),
        None,
        None,
    );
    Ok(ActionOutcome::Continue)
}

fn accept_action(
    core: &mut SessionCore,
    phase: Option<Phase>,
    call: StoredCall,
) -> Result<ActionOutcome, TnLlamaError> {
    let task_id = core.outstanding.as_ref().and_then(|turn| turn.task_id);
    let slot_id = core.outstanding.as_ref().and_then(|turn| turn.slot_id);
    let required = required_tools(core);
    let executed = core
        .governed_tool_exchanges
        .iter()
        .map(|exchange| exchange.call.name.clone())
        .collect::<BTreeSet<_>>();

    if call.name == "emit_governed_record" {
        if required.iter().any(|name| !executed.contains(name)) {
            return Err(terminalize(
                core,
                session_error(
                    "tn_required_tool_missing",
                    "all selected-section governed tools must execute before emission",
                ),
                FailedSink::None,
            ));
        }
        return accept_report_emission(
            core,
            phase.expect("report requires model decision"),
            call,
            task_id,
            slot_id,
        );
    }

    if !required.contains(&call.name) {
        return Err(terminalize(
            core,
            session_error(
                "tn_action_not_allowed",
                "model action is not allowed by the selected-section contract",
            ),
            FailedSink::None,
        ));
    }
    if executed.contains(&call.name) {
        return Err(terminalize(
            core,
            session_error(
                "tn_tool_already_executed",
                "configured governed tool cannot execute twice in one session",
            ),
            FailedSink::None,
        ));
    }
    if core.governed.is_some() {
        return accept_native_tool(core, phase, call, task_id, slot_id);
    }
    let row = &core.admitted_request().request.row;
    let context = ToolContext {
        run_id: core.run_id.clone(),
        source_device_identity: row.device_identity().to_string(),
        source_event_id: row.event_id().to_string(),
        source_event_type: row.event_type().to_string(),
        source_row_hash: row.row_hash().to_string(),
        selected_sections: core.selected_sections.clone(),
        action: core.report_contract.operation.clone(),
    };
    let arguments =
        crate::envelope::parse_duplicate_safe_json(call.arguments.as_bytes()).map_err(|_| {
            terminalize(
                core,
                session_error(
                    "tn_tool_arguments_invalid",
                    "protected tool arguments must be an empty object",
                ),
                FailedSink::None,
            )
        })?;
    if !arguments
        .as_object()
        .is_some_and(|arguments| arguments.is_empty())
    {
        return Err(terminalize(
            core,
            session_error(
                "tn_tool_arguments_invalid",
                "protected tool arguments must be an empty object",
            ),
            FailedSink::None,
        ));
    }
    let registered_call = RegisteredCall {
        id: call.id.clone(),
        name: call.name.clone(),
        arguments: serde_json::to_vec(
            &serde_json::json!({"source_event_id":context.source_event_id,"action":context.action}),
        )
        .expect("trusted invocation serializes"),
    };
    let receipt = match core.tool_dispatcher.execute(&registered_call, &context) {
        Ok(ToolReceipt::Compliance(receipt)) => receipt,
        Err(error) => return Err(terminalize(core, error, FailedSink::None)),
    };
    let receipt_value = serde_json::to_value(&receipt).map_err(|_| {
        terminalize(
            core,
            session_error(
                "tn_tool_receipt_invalid",
                "server tool receipt could not be serialized",
            ),
            FailedSink::None,
        )
    })?;
    let receipt_json = tn_core::canonical::canonical_bytes(&receipt_value)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or_else(|| {
            terminalize(
                core,
                session_error(
                    "tn_tool_receipt_invalid",
                    "server tool receipt could not be canonically serialized",
                ),
                FailedSink::None,
            )
        })?;
    let events: &[&str] = if call.origin == CallOrigin::Runtime {
        &[
            "governed_tool_executed_runtime",
            "tool_result_accepted_runtime",
        ]
    } else {
        &["governed_tool_executed"]
    };
    for kind in events {
        if append_audit(
            core,
            kind,
            State::GovernedAction,
            State::GovernedAction,
            phase,
            task_id,
            slot_id,
            "allow",
            None,
            AuditFacts {
                content_digest: Some(audit_digest(&model_request_digest(receipt_json.as_bytes()))),
                incomplete: Some(false),
                ..AuditFacts::default()
            },
        )
        .is_err()
        {
            return Err(terminalize(
                core,
                session_error(
                    "tn_audit_append_failed",
                    "governed-tool audit append failed",
                ),
                FailedSink::Audit,
            ));
        }
    }
    let trace_row_hash = receipt.row_hash.clone();
    let receipt_event_id = receipt.event_id.clone();
    let tool_name = call.name.clone();
    consume_outstanding(core);
    core.compliance_receipt = Some(receipt);
    push_client_trace(
        core,
        if call.origin == CallOrigin::Runtime {
            "tool_executed_runtime"
        } else {
            "tool_executed"
        },
        State::GovernedAction,
        task_id,
        slot_id,
        Some(trace_row_hash.clone()),
        Some(tool_name.clone()),
        Some(receipt_event_id.clone()),
    );
    push_client_trace(
        core,
        "receipt_inserted",
        State::GovernedAction,
        task_id,
        slot_id,
        Some(trace_row_hash),
        Some(tool_name),
        Some(receipt_event_id),
    );
    core.governed_tool_exchanges.push(StoredToolExchange {
        call,
        result: receipt_json,
    });
    Ok(ActionOutcome::Continue)
}

fn available_section_manifest(
    core: &SessionCore,
) -> Result<BTreeMap<String, Vec<String>>, TnLlamaError> {
    let encrypted = if core.governed.is_some() {
        core.governed_request()
            .object
            .group_names()
            .into_iter()
            .filter(|name| *name != "tn.agents")
            .map(|name| {
                (
                    name.to_string(),
                    core.governed_request().object.envelope()[name]["field_hashes"]
                        .as_object()
                        .expect("native field hashes")
                        .keys()
                        .cloned()
                        .collect(),
                )
            })
            .collect()
    } else {
        core.admitted_request()
            .request
            .row
            .encrypted_group_manifest()
    };
    let mut manifest = BTreeMap::new();
    for name in &core.report_contract.allowed_input_sections {
        let Some(fields) = encrypted.get(name) else {
            continue;
        };
        let mut names = fields.clone();
        names.sort();
        manifest.insert(name.clone(), names);
    }
    if manifest.is_empty() {
        Err(session_error(
            "tn_section_selection_invalid",
            "admitted row contains no configured input sections",
        ))
    } else {
        Ok(manifest)
    }
}

fn available_action_tools(core: &SessionCore) -> Result<Vec<Value>, TnLlamaError> {
    let executed = core
        .governed_tool_exchanges
        .iter()
        .map(|exchange| exchange.call.name.clone())
        .collect::<BTreeSet<_>>();
    let pending = required_tools(core)
        .difference(&executed)
        .cloned()
        .collect::<Vec<_>>();
    if pending.is_empty() {
        return Ok(vec![crate::model_protocol::native_report_tool()]);
    }
    pending
        .iter()
        .map(|name| {
            let spec = core.tool_dispatcher.specification(name).ok_or_else(|| {
                session_error(
                    "tn_tool_not_registered",
                    "required governed tool is absent from the registry",
                )
            })?;
            Ok(if core.governed.is_some() {
                spec.native_model_tool()
            } else {
                spec.model_tool()
            })
        })
        .collect()
}

fn advance_runtime_actions(core: &mut SessionCore) -> Result<(), TnLlamaError> {
    let result = (|| {
        if core.state == State::SectionSelection && core.governed.is_none() {
            let manifest = available_section_manifest(core)?;
            if manifest.len() != 1 {
                return Ok(());
            }
            let sections = manifest.into_keys().collect::<BTreeSet<_>>();
            let call = StoredCall {
                origin: CallOrigin::Runtime,
                id: format!("runtime:{}:selection", core.run_id),
                name: "select_sections".into(),
                arguments: serde_json::json!({"sections": sections}).to_string(),
            };
            let arguments: Value =
                serde_json::from_str(&call.arguments).expect("runtime selection JSON");
            let sections = validate_section_selection_arguments(core, &arguments)?;
            apply_section_selection(core, None, call, sections)?;
        }
        while core.state == State::GovernedAction {
            let tools = available_action_tools(core)?;
            let Some((name, arguments)) = crate::model_protocol::determined_tool_call(&tools)
            else {
                break;
            };
            let call = StoredCall {
                origin: CallOrigin::Runtime,
                id: format!(
                    "runtime:{}:tool:{}",
                    core.run_id,
                    core.governed_tool_exchanges.len()
                ),
                name,
                arguments,
            };
            accept_action(core, None, call)?;
        }
        Ok(())
    })();
    result.map_err(|error| {
        if core.state == State::Failed {
            error
        } else {
            terminalize(core, error, FailedSink::None)
        }
    })
}

fn selected_values(core: &SessionCore) -> Result<BTreeMap<String, Value>, TnLlamaError> {
    core.selected_sections
        .iter()
        .map(|name| {
            core.opened_sections
                .get(name)
                .cloned()
                .map(|value| (name.clone(), value))
                .ok_or_else(|| {
                    session_error(
                        "tn_session_state",
                        "selected protected section is no longer available",
                    )
                })
        })
        .collect()
}

fn requires_source_governance(core: &SessionCore) -> bool {
    core.selected_sections.iter().any(|section| {
        core.report_contract
            .section_rules
            .get(section)
            .is_some_and(|rule| rule.propagate_source_governance)
    })
}

fn required_attributions(core: &SessionCore) -> Vec<String> {
    core.selected_sections
        .iter()
        .filter_map(|section| {
            core.report_contract
                .section_rules
                .get(section)
                .and_then(|rule| rule.required_attribution.clone())
        })
        .collect()
}

fn required_tools(core: &SessionCore) -> BTreeSet<String> {
    core.selected_sections
        .iter()
        .filter_map(|section| {
            core.report_contract
                .section_rules
                .get(section)
                .and_then(|rule| rule.required_tool.clone())
        })
        .collect()
}

fn trusted_source_lineage(core: &SessionCore) -> Result<Option<SourceLineage>, TnLlamaError> {
    if !requires_source_governance(core) {
        return Ok(None);
    }
    let governance = core
        .governance
        .as_ref()
        .ok_or_else(|| session_error("tn_session_state", "verified governance is unavailable"))?;
    let source_policy = governance
        .plaintext
        .get("policy")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            session_error(
                "tn_session_state",
                "verified source governance policy is unavailable",
            )
        })?;
    let row = &core.admitted_request().request.row;
    Ok(Some(SourceLineage {
        source_device_identity: row.device_identity().to_string(),
        source_event_id: row.event_id().to_string(),
        source_event_type: row.event_type().to_string(),
        derived_from_row_hash: row.row_hash().to_string(),
        source_policy: source_policy.to_string(),
        selected_sections: core.selected_sections.iter().cloned().collect(),
        operation: core.report_contract.operation.clone(),
    }))
}

fn governance_identity_facts(core: &SessionCore) -> AuditFacts {
    AuditFacts {
        governance_context_protocol: Some("tn.llama.governance-context.v1".into()),
        source_object_id: core.governed.as_ref().map(|_| core.row_hash.clone()),
        source_row_hash: core.governed.is_none().then(|| core.row_hash.clone()),
        ..AuditFacts::default()
    }
}

fn admit_governance(core: &mut SessionCore) -> Result<(), TnLlamaError> {
    let result = if let Some(state) = &core.governed {
        (|| {
            let groups = available_section_manifest(core)?.into_keys().collect();
            state
                .input
                .governance(core.governed_request(), &groups)
                .map(|(view, governance)| (Some(view), governance))
        })()
    } else {
        core.governance_reader
            .open_and_verify(&core.admitted_request().request.row)
            .map(|governance| (None, governance))
    };
    let (view, governance) = result.map_err(|error| terminalize(core, error, FailedSink::None))?;
    if let Some(state) = &mut core.governed {
        state.view = view;
    }
    let mut facts = governance_identity_facts(core);
    facts.governance_value_count =
        Some(u32::try_from(governance.plaintext.len()).expect("governance count fits u32"));
    facts.governance_commitment_count =
        Some(u32::try_from(governance.commitments.len()).expect("commitment count fits u32"));
    facts.hashes_verified = Some(true);
    core.governance = Some(governance);
    // Resolve authenticated dependencies before any model permit can be issued.
    model_governance(core).map_err(|error| terminalize(core, error, FailedSink::None))?;
    if append_audit(
        core,
        "governance_opened_and_verified",
        State::GovernanceAdmission,
        State::SectionSelection,
        None,
        None,
        None,
        "allow",
        None,
        facts,
    )
    .is_err()
    {
        return Err(terminalize(
            core,
            session_error(
                "tn_audit_append_failed",
                "governance admission audit append failed",
            ),
            FailedSink::Audit,
        ));
    }
    let row_hash = core.row_hash.clone();
    push_client_trace(
        core,
        "governance_opened",
        State::SectionSelection,
        None,
        None,
        Some(row_hash),
        None,
        None,
    );
    core.state = State::SectionSelection;
    Ok(())
}

fn model_governance(core: &mut SessionCore) -> Result<BTreeMap<String, Value>, TnLlamaError> {
    let governance = core
        .governance
        .as_ref()
        .ok_or_else(|| session_error("tn_session_state", "verified governance is unavailable"))?;
    let Some(state) = &core.governed else {
        return Ok(governance.plaintext.clone());
    };
    let view = state.view.as_ref().ok_or_else(|| {
        session_error(
            "tn_session_state",
            "verified source governance is unavailable",
        )
    })?;
    // The request and its admitted inputs are fixed; only a tool object can change the context.
    let tools: Vec<String> = state
        .tools
        .iter()
        .map(|tool| tool.object.id().to_owned())
        .collect();
    if let Some((cached, context)) = &state.context {
        if *cached == tools {
            return Ok(context.clone());
        }
    }
    let context = state
        .input
        .decision_context(core.governed_request(), view, &state.tools)?;
    if let Some(state) = core.governed.as_mut() {
        state.context = Some((tools, context.clone()));
    }
    Ok(context)
}

fn governed_action_request(
    core: &SessionCore,
    governance_context: &BTreeMap<String, Value>,
) -> Result<Vec<u8>, TnLlamaError> {
    if core.governed.is_some() {
        let tools = available_action_tools(core)?;
        let exchanges = core
            .governed_tool_exchanges
            .iter()
            .map(|exchange| ToolExchange {
                call: stored_call(&exchange.call),
                result: &exchange.result,
            })
            .collect::<Vec<_>>();
        let (governance_hash, _) = governed_hash_keys(core)?;
        let decrypt_call = core.selection_call.as_ref().ok_or_else(|| {
            session_error("tn_session_state", "decrypt call history is unavailable")
        })?;
        return crate::model_protocol::governed_object_action_body(
            &core.user_content,
            &selected_values(core)?,
            &governance_hash,
            stored_call(decrypt_call),
            governance_context,
            core.governed
                .as_ref()
                .and_then(|state| state.input.report_policy.as_ref()),
            &required_attributions(core),
            core.governed_request().object.id(),
            &core.report_contract.operation,
            tools,
            &exchanges,
            core.final_max_tokens,
        );
    }
    let available_sections = available_section_manifest(core)?;
    let selected_values = selected_values(core)?;
    let selected_sections = core.selected_sections.iter().cloned().collect::<Vec<_>>();
    let source_lineage = trusted_source_lineage(core)?;
    let attributions = required_attributions(core);
    let tools = available_action_tools(core)?;
    let selection_call = core.selection_call.as_ref().ok_or_else(|| {
        session_error(
            "tn_session_state",
            "section-selection call history is unavailable",
        )
    })?;
    let exchanges = core
        .governed_tool_exchanges
        .iter()
        .map(|exchange| ToolExchange {
            call: stored_call(&exchange.call),
            result: &exchange.result,
        })
        .collect::<Vec<_>>();
    governed_action_body(GovernedActionBodyInput {
        user_content: &core.user_content,
        available_sections: &available_sections,
        selected_values: &selected_values,
        selected_sections: &selected_sections,
        applicable_governance: Some(governance_context),
        output_event_type: &core.report_contract.output_event_type,
        output_public_section: &core.report_contract.output_public_section,
        operation: &core.report_contract.operation,
        output_policy: &core.report_contract.output_policy,
        required_attributions: &attributions,
        source_lineage: source_lineage.as_ref(),
        selection_call: stored_call(selection_call),
        tool_exchanges: &exchanges,
        tools,
        max_tokens: core.final_max_tokens,
    })
}

fn accept_native_tool(
    core: &mut SessionCore,
    phase: Option<Phase>,
    call: StoredCall,
    task_id: Option<i64>,
    slot_id: Option<i32>,
) -> Result<ActionOutcome, TnLlamaError> {
    if core
        .selection_call
        .iter()
        .chain(
            core.governed_tool_exchanges
                .iter()
                .map(|exchange| &exchange.call),
        )
        .any(|previous| previous.id == call.id)
    {
        return Err(terminalize(
            core,
            session_error(
                "tn_tool_call_replayed",
                "native tool call identity was already used",
            ),
            FailedSink::None,
        ));
    }
    let state = core.governed.as_ref().expect("native session");
    let context = crate::tools::NativeToolContext {
        run_id: &core.run_id,
        data: state.data.as_ref().expect("selected data"),
        request: core.governed_request(),
        source: state.view.as_ref().expect("accepted governance"),
        input: &state.input,
        selected_sections: &core.selected_sections,
        action: &core.report_contract.operation,
    };
    let result = core.tool_dispatcher.execute_native(
        &RegisteredCall {
            id: call.id.clone(),
            name: call.name.clone(),
            arguments: call.arguments.as_bytes().to_vec(),
        },
        &context,
    );
    let receipt = result.map_err(|error| terminalize(core, error, FailedSink::None))?;
    audit_object_register(core, &receipt.publication, phase, task_id, slot_id)?;
    let receipt_json = tn_core::canonical::canonical_bytes(&receipt.receipt)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or_else(|| {
            terminalize(
                core,
                session_error(
                    "tn_tool_receipt_invalid",
                    "native receipt serialization failed",
                ),
                FailedSink::None,
            )
        })?;
    let receipt_digest = model_request_digest(receipt_json.as_bytes());
    for kind in if call.origin == CallOrigin::Runtime {
        [
            "governed_tool_executed_runtime",
            "tool_result_accepted_runtime",
        ]
    } else {
        ["governed_tool_executed", "tool_result_accepted"]
    } {
        if append_audit(
            core,
            kind,
            State::GovernedAction,
            State::GovernedAction,
            phase,
            task_id,
            slot_id,
            "allow",
            None,
            AuditFacts {
                content_digest: Some(audit_digest(&receipt_digest)),
                incomplete: Some(false),
                ..AuditFacts::default()
            },
        )
        .is_err()
        {
            return Err(terminalize(
                core,
                session_error(
                    "tn_audit_append_failed",
                    "native tool acceptance audit failed",
                ),
                FailedSink::Audit,
            ));
        }
    }
    let object_id = receipt.publication.object.id().to_owned();
    for event in if call.origin == CallOrigin::Runtime {
        ["tool_executed_runtime", "receipt_inserted"]
    } else {
        ["tool_executed", "receipt_inserted"]
    } {
        push_client_trace(
            core,
            event,
            State::GovernedAction,
            task_id,
            slot_id,
            Some(object_id.clone()),
            Some(call.name.clone()),
            Some(object_id.clone()),
        );
    }
    core.governed
        .as_mut()
        .expect("native session")
        .tools
        .push(receipt.publication);
    core.governed_tool_exchanges.push(StoredToolExchange {
        call,
        result: receipt_json,
    });
    consume_outstanding(core);
    Ok(ActionOutcome::Continue)
}

fn accept_governed_report(
    core: &mut SessionCore,
    phase: Phase,
    call: StoredCall,
    task_id: Option<i64>,
    slot_id: Option<i32>,
) -> Result<ActionOutcome, TnLlamaError> {
    let result = (|| {
        let html = parse_report_html(&call.arguments)?;
        validate_html_attributions(core, &html)?;
        let state = core.governed.as_ref().expect("governed session");
        state.output.emit(
            state.data.as_ref().expect("selected data"),
            &html,
            &core.report_contract.output_event_type,
            core.governed_request(),
            state.view.as_ref().expect("accepted governance"),
            &state.input,
            &state.tools,
        )
    })();
    let publication = match result {
        Ok(output) => output,
        Err(error) => return Err(terminalize(core, error, FailedSink::None)),
    };
    audit_object_register(core, &publication, Some(phase), task_id, slot_id)?;
    let output = publication.object;
    if append_audit(
        core,
        "output_emitted_and_read_back",
        State::GovernedAction,
        State::GovernedAction,
        Some(phase),
        task_id,
        slot_id,
        "allow",
        None,
        AuditFacts::default(),
    )
    .is_err()
    {
        return Err(terminalize(
            core,
            session_error(
                "tn_audit_append_failed",
                "output readback audit append failed",
            ),
            FailedSink::Audit,
        ));
    }
    let source_object_id = core.governed_request().object.id().to_owned();
    push_client_trace(
        core,
        "output_readback",
        State::GovernedAction,
        task_id,
        slot_id,
        Some(output.id().to_owned()),
        Some(call.name),
        Some(output.id().to_owned()),
    );
    if append_audit(
        core,
        "standalone_use_completed",
        State::GovernedAction,
        State::Complete,
        Some(phase),
        task_id,
        slot_id,
        "allow",
        None,
        AuditFacts::default(),
    )
    .is_err()
    {
        return Err(terminalize(
            core,
            session_error(
                "tn_audit_append_failed",
                "standalone completion audit append failed",
            ),
            FailedSink::Audit,
        ));
    }
    let admitted = core.admitted.take().expect("active session");
    if let Err(error) = admitted.commit() {
        return Err(terminalize(core, error, FailedSink::None));
    }
    push_client_trace(
        core,
        "release",
        State::Complete,
        task_id,
        slot_id,
        Some(output.id().to_owned()),
        None,
        Some(output.id().to_owned()),
    );
    let release = crate::GovernedReportRelease {
        protocol: "tn.llama.release.v2",
        run_id: core.run_id.clone(),
        source_object_id,
        output_object_id: output.id().to_owned(),
        output_object: output.wire().to_owned(),
        tool_objects: core
            .governed
            .as_ref()
            .expect("native session")
            .tools
            .iter()
            .map(|tool| tool.object.wire().to_owned())
            .collect(),
        trace: core.client_trace.clone(),
    };
    let release_bytes = release
        .to_json_bytes()
        .map_err(|error| terminalize(core, error, FailedSink::None))?;
    if core
        .trace
        .append(SensitiveTraceEvent {
            run_id: &core.run_id,
            phase: Some(phase),
            kind: SensitiveTraceKind::Release,
            task_id,
            slot_id,
            request_json: None,
            rendered_prompt: None,
            runnable_manifest: None,
            raw_model_output: None,
            parsed_content: Some(&release_bytes),
            error_code: None,
        })
        .is_err()
    {
        return Err(terminalize(
            core,
            session_error(
                "tn_sensitive_trace_append_failed",
                "closed native release trace append failed",
            ),
            FailedSink::Trace,
        ));
    }
    consume_outstanding(core);
    core.state = State::Complete;
    Ok(ActionOutcome::GovernedRelease(release))
}

fn audit_object_register(
    core: &mut SessionCore,
    publication: &crate::output_tn::GovernedPublication,
    phase: Option<Phase>,
    task_id: Option<i64>,
    slot_id: Option<i32>,
) -> Result<(), TnLlamaError> {
    let failed = publication.register_error.is_some();
    let outcome = if failed {
        "error"
    } else if publication.register_enabled {
        "recorded"
    } else {
        "disabled"
    };
    let mut event = AuditEvent::transition(
        "governed_action",
        "governed_action",
        publication.object.id(),
        outcome,
    );
    event.kind = "object_release_register".into();
    event.request_digest = core.request_digest().into();
    event.llama_task_id = task_id;
    event.llama_slot_id = slot_id;
    event.facts.phase = phase;
    event.error_code = failed.then(|| "tn_object_register_failed".into());
    core.audit.append(event).map(|_| ()).map_err(|_| {
        terminalize(
            core,
            session_error(
                "tn_audit_append_failed",
                "object register outcome audit append failed",
            ),
            FailedSink::Audit,
        )
    })
}

fn accept_report_emission(
    core: &mut SessionCore,
    phase: Phase,
    call: StoredCall,
    task_id: Option<i64>,
    slot_id: Option<i32>,
) -> Result<ActionOutcome, TnLlamaError> {
    if core.governed.is_some() {
        return accept_governed_report(core, phase, call, task_id, slot_id);
    }
    let html = parse_report_html(&call.arguments)
        .map_err(|error| terminalize(core, error, FailedSink::None))?;
    if let Err(error) = validate_html_attributions(core, &html) {
        return Err(terminalize(core, error, FailedSink::None));
    }
    let source_lineage = match trusted_source_lineage(core) {
        Ok(lineage) => lineage,
        Err(error) => return Err(terminalize(core, error, FailedSink::None)),
    };
    let trusted = TrustedDerivation {
        contract: (*core.report_contract).clone(),
        source_lineage,
        compliance_evidence: core.compliance_receipt.clone(),
        request_digest: core.request_digest.clone(),
    };
    let policy = &core.report_contract.output_policy;
    let proposal = ReportProposal {
        event_type: core.report_contract.output_event_type.clone(),
        public_sections: crate::output_tn::ReportPublicSections {
            default: crate::output_tn::DefaultReportSection { report_html: html },
        },
        governance: crate::output_tn::ProposedOutputGovernance {
            instruction: policy.instruction.clone(),
            use_for: policy.use_for.clone(),
            do_not_use_for: policy.do_not_use_for.clone(),
            consequences: policy.consequences.clone(),
            on_violation_or_error: policy.on_violation_or_error.clone(),
            source_lineage: trusted.source_lineage.clone(),
            compliance_evidence: trusted.compliance_evidence.clone(),
        },
    };
    let verified = match core
        .output_publisher
        .as_ref()
        .expect("legacy publisher")
        .emit_report(&proposal, &trusted)
    {
        Ok(verified) => verified,
        Err(error) => return Err(terminalize(core, error, FailedSink::None)),
    };
    if append_audit(
        core,
        "output_emitted_and_read_back",
        State::GovernedAction,
        State::GovernedAction,
        Some(phase),
        task_id,
        slot_id,
        "allow",
        None,
        AuditFacts::default(),
    )
    .is_err()
    {
        return Err(terminalize(
            core,
            session_error(
                "tn_audit_append_failed",
                "output emission/readback audit append failed",
            ),
            FailedSink::Audit,
        ));
    }
    push_client_trace(
        core,
        "output_emitted",
        State::GovernedAction,
        task_id,
        slot_id,
        Some(verified.row_hash.clone()),
        Some(call.name.clone()),
        Some(verified.event_id.clone()),
    );
    push_client_trace(
        core,
        "output_readback",
        State::GovernedAction,
        task_id,
        slot_id,
        Some(verified.row_hash.clone()),
        Some(call.name),
        Some(verified.event_id.clone()),
    );

    let source_event_id = core.admitted_request().request.row.event_id().to_string();
    let source_row_hash = core.row_hash.clone();
    let admitted = core
        .admitted
        .take()
        .expect("active report-emission session is admitted");
    if let Err(error) = admitted.commit() {
        return Err(terminalize(core, error, FailedSink::None));
    }
    if append_audit(
        core,
        "source_chain_committed",
        State::GovernedAction,
        State::Complete,
        Some(phase),
        task_id,
        slot_id,
        "allow",
        None,
        AuditFacts::default(),
    )
    .is_err()
    {
        return Err(terminalize(
            core,
            session_error(
                "tn_audit_append_failed",
                "source-chain commit audit append failed",
            ),
            FailedSink::Audit,
        ));
    }
    push_client_trace(
        core,
        "source_chain_committed",
        State::Complete,
        task_id,
        slot_id,
        Some(source_row_hash.clone()),
        None,
        Some(source_event_id.clone()),
    );
    push_client_trace(
        core,
        "release",
        State::Complete,
        task_id,
        slot_id,
        Some(verified.row_hash.clone()),
        None,
        Some(verified.event_id.clone()),
    );
    let release = ReportRelease {
        protocol: RELEASE_PROTOCOL,
        run_id: core.run_id.clone(),
        source_event_id,
        source_row_hash,
        output_event_id: verified.event_id,
        output_row_hash: verified.row_hash,
        output_ndjson: verified.ndjson,
        trace: core.client_trace.clone(),
    };
    let release_bytes = release
        .to_json_bytes()
        .map_err(|error| terminalize(core, error, FailedSink::None))?;
    if core
        .trace
        .append(SensitiveTraceEvent {
            run_id: &core.run_id,
            phase: Some(phase),
            kind: SensitiveTraceKind::Release,
            task_id,
            slot_id,
            request_json: None,
            rendered_prompt: None,
            runnable_manifest: None,
            raw_model_output: None,
            parsed_content: Some(&release_bytes),
            error_code: None,
        })
        .is_err()
    {
        return Err(terminalize(
            core,
            session_error(
                "tn_sensitive_trace_append_failed",
                "closed release trace append failed",
            ),
            FailedSink::Trace,
        ));
    }
    consume_outstanding(core);
    core.state = State::Complete;
    Ok(ActionOutcome::Release(release))
}

fn parse_report_html(arguments: &str) -> Result<String, TnLlamaError> {
    let value = crate::envelope::parse_duplicate_safe_json(arguments.as_bytes()).map_err(|_| {
        session_error(
            "tn_report_proposal_invalid",
            "report proposal is not duplicate-free JSON",
        )
    })?;
    let fields = value
        .as_object()
        .filter(|value| exact_keys(value, &["report_html"]))
        .ok_or_else(|| {
            session_error(
                "tn_report_proposal_invalid",
                "report proposal must contain report_html only",
            )
        })?;
    fields["report_html"]
        .as_str()
        .filter(|html| !html.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            session_error(
                "tn_report_proposal_invalid",
                "report content must be nonempty text",
            )
        })
}

fn validate_html_attributions(core: &SessionCore, html: &str) -> Result<(), TnLlamaError> {
    let visible_text = human_visible_html_text(html);
    for (section, rule) in &core.report_contract.section_rules {
        let Some(attribution) = &rule.required_attribution else {
            continue;
        };
        if core.selected_sections.contains(section) {
            if !visible_text.contains(attribution) {
                return Err(session_error(
                    "tn_required_attribution_missing",
                    "report omitted a selected section's exact human-visible attribution",
                ));
            }
        } else if visible_text.contains(attribution) || html.contains(attribution) {
            return Err(session_error(
                "tn_unselected_attribution_present",
                "report carried attribution for an unselected section",
            ));
        }
    }
    Ok(())
}

fn human_visible_html_text(html: &str) -> String {
    struct OpenElement {
        name: String,
        hides_content: bool,
        raw_text: bool,
    }

    let mut visible = String::with_capacity(html.len());
    let mut tag = String::new();
    let mut inside_tag = false;
    let mut attribute_quote: Option<char> = None;
    let mut open_elements: Vec<OpenElement> = Vec::new();
    let mut embedded_stylesheet = false;
    for character in html.chars() {
        match character {
            '<' if !inside_tag => {
                inside_tag = true;
                tag.clear();
                attribute_quote = None;
            }
            character @ ('\'' | '"') if inside_tag => {
                if attribute_quote == Some(character) {
                    attribute_quote = None;
                } else if attribute_quote.is_none() {
                    attribute_quote = Some(character);
                }
                tag.push(character);
            }
            '>' if inside_tag && attribute_quote.is_none() => {
                inside_tag = false;
                let tag_body = tag.trim();
                let is_closing = tag_body.starts_with('/');
                let tag_name = tag_body
                    .strip_prefix('/')
                    .unwrap_or(tag_body)
                    .trim_start()
                    .split(|character: char| character.is_ascii_whitespace() || character == '/')
                    .next()
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                if open_elements.last().is_some_and(|element| element.raw_text) {
                    if is_closing
                        && open_elements
                            .last()
                            .is_some_and(|element| element.name == tag_name)
                    {
                        open_elements.pop();
                    }
                } else if is_closing {
                    if let Some(position) = open_elements
                        .iter()
                        .rposition(|element| element.name == tag_name)
                    {
                        open_elements.truncate(position);
                    }
                } else if !is_void_html_element(&tag_name) {
                    embedded_stylesheet |= tag_name == "style";
                    open_elements.push(OpenElement {
                        hides_content: matches!(tag_name.as_str(), "script" | "style" | "template")
                            || tag_explicitly_hides_content(tag_body),
                        raw_text: matches!(tag_name.as_str(), "script" | "style"),
                        name: tag_name,
                    });
                }
            }
            _ if inside_tag => tag.push(character),
            _ if open_elements.iter().all(|element| !element.hides_content) => {
                visible.push(character)
            }
            _ => {}
        }
    }
    if embedded_stylesheet {
        String::new()
    } else {
        visible
    }
}

fn is_void_html_element(tag_name: &str) -> bool {
    matches!(
        tag_name,
        "area"
            | "base"
            | "br"
            | "col"
            | "embed"
            | "hr"
            | "img"
            | "input"
            | "link"
            | "meta"
            | "param"
            | "source"
            | "track"
            | "wbr"
    )
}

fn tag_explicitly_hides_content(tag_body: &str) -> bool {
    let Some((_, attributes)) = tag_body.split_once(char::is_whitespace) else {
        return false;
    };
    let attributes = attributes.to_ascii_lowercase();
    let compact: String = attributes
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    let has_hidden = attributes
        .split_ascii_whitespace()
        .any(|token| token == "hidden" || token.starts_with("hidden="));
    has_hidden
        || compact.contains("aria-hidden=\"true\"")
        || compact.contains("aria-hidden='true'")
        || compact.contains("aria-hidden=true")
        || (compact.contains("style=")
            && (compact.contains("display:none") || compact.contains("visibility:hidden")))
}

#[allow(clippy::too_many_arguments)]
fn push_client_trace(
    core: &mut SessionCore,
    event: &str,
    state: State,
    task_id: Option<i64>,
    slot_id: Option<i32>,
    row_hash: Option<String>,
    tool_name: Option<String>,
    event_id: Option<String>,
) {
    core.client_trace.push(ClientTraceEvent {
        ordinal: u64::try_from(core.client_trace.len() + 1).expect("trace length fits u64"),
        event: event.to_string(),
        state: state.as_str().to_string(),
        task_id,
        slot_id,
        row_hash,
        selected_sections: core.selected_sections.iter().cloned().collect(),
        tool_name,
        event_id,
    });
}

fn validate_identity(core: &SessionCore, permit: &TurnPermit) -> Result<(), TnLlamaError> {
    if core.run_id != permit.run_id {
        return Err(session_error(
            "tn_turn_session_mismatch",
            "turn permit run ID does not match the session",
        ));
    }
    let outstanding = core
        .outstanding
        .as_ref()
        .ok_or_else(|| session_error("tn_turn_consumed", "turn permit is no longer outstanding"))?;
    if core.state.phase() != Some(permit.phase) {
        return Err(session_error(
            "tn_turn_phase_mismatch",
            "turn permit phase is not the authoritative session phase",
        ));
    }
    if outstanding.serial != permit.serial {
        return Err(session_error(
            "tn_turn_consumed",
            "turn permit serial is no longer current",
        ));
    }
    if outstanding.phase != permit.phase {
        return Err(session_error(
            "tn_turn_phase_mismatch",
            "turn permit phase differs from the outstanding turn",
        ));
    }
    Ok(())
}

fn validate_begun(core: &SessionCore, permit: &TurnPermit) -> Result<(), TnLlamaError> {
    validate_identity(core, permit)?;
    let outstanding = core.outstanding.as_ref().expect("identity checked");
    if outstanding.lifecycle != PermitLifecycle::Begun {
        return Err(session_error(
            "tn_turn_not_begun",
            "only a begun turn permit can accept a model result",
        ));
    }
    Ok(())
}

fn validate_native_call(
    core: &SessionCore,
    phase: Phase,
    result: &NativeToolResult<'_>,
) -> Result<StoredCall, TnLlamaError> {
    if result.truncated || result.stop_limit {
        return Err(session_error(
            "tn_model_turn_incomplete",
            "tool model turn ended incomplete",
        ));
    }
    if !result.content.is_empty() {
        return Err(session_error(
            "tn_model_prose_not_allowed",
            "model action must contain exactly one tool call and empty parsed assistant content",
        ));
    }
    if result.call_count != 1 || result.call.is_none() {
        return Err(session_error(
            "tn_tool_call_count",
            "tool model turn must contain exactly one native call",
        ));
    }
    let call = result.call.as_ref().expect("count and option checked");
    let id = std::str::from_utf8(call.id)
        .ok()
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            session_error(
                "tn_tool_call_id_invalid",
                "native tool call ID must be nonempty UTF-8",
            )
        })?;
    let expected_name = match phase {
        Phase::GovernanceRead | Phase::CommitmentEcho => {
            return Err(session_error(
                "tn_turn_phase_mismatch",
                "reserved model phase cannot accept a result",
            ))
        }
        Phase::SectionSelection if core.governed.is_some() => "decrypt_value",
        Phase::SectionSelection => "select_sections",
        Phase::GovernedAction => std::str::from_utf8(call.name)
            .ok()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                session_error(
                    "tn_tool_name_invalid",
                    "native tool name must be nonempty UTF-8",
                )
            })?,
    };
    if call.name != expected_name.as_bytes() {
        return Err(session_error(
            "tn_action_not_allowed",
            "model action is not allowed in the current state",
        ));
    }
    let arguments_value = crate::envelope::parse_duplicate_safe_json(call.parsed_arguments)
        .map_err(|_| {
            session_error(
                "tn_tool_arguments_invalid",
                "native parsed tool arguments are not duplicate-free JSON",
            )
        })?;
    let arguments = std::str::from_utf8(call.parsed_arguments).map_err(|_| {
        session_error(
            "tn_tool_arguments_invalid",
            "native parsed tool arguments are not UTF-8 JSON",
        )
    })?;
    match phase {
        Phase::GovernanceRead | Phase::CommitmentEcho => unreachable!("reserved phase rejected"),
        Phase::SectionSelection => {
            selection_arguments(core, &arguments_value)?;
        }
        Phase::GovernedAction => {}
    }
    Ok(StoredCall {
        origin: CallOrigin::Model,
        id: id.to_string(),
        name: expected_name.to_string(),
        arguments: arguments.to_string(),
    })
}

fn selection_arguments(
    core: &SessionCore,
    arguments: &Value,
) -> Result<BTreeSet<String>, TnLlamaError> {
    if core.governed.is_some() {
        validate_decrypt_arguments(core, arguments)
    } else {
        validate_section_selection_arguments(core, arguments)
    }
}

/// The hash key of the governance object and the hash keys of the encrypted data.
fn governed_hash_keys(
    core: &SessionCore,
) -> Result<(String, BTreeMap<String, BTreeMap<String, String>>), TnLlamaError> {
    let envelope = core.governed_request().object.envelope();
    let governance_hash = envelope["tn.agents"]["field_hashes"]["policy"]
        .as_str()
        .ok_or_else(|| session_error("tn_session_state", "governance hash key is unavailable"))?
        .to_owned();
    let encrypted = available_section_manifest(core)?
        .into_keys()
        .map(|section| {
            let hashes = serde_json::from_value(envelope[&section]["field_hashes"].clone())
                .map_err(|_| {
                    session_error("tn_session_state", "data hash keys are unavailable")
                })?;
            Ok((section, hashes))
        })
        .collect::<Result<_, TnLlamaError>>()?;
    Ok((governance_hash, encrypted))
}

fn validate_decrypt_arguments(
    core: &SessionCore,
    arguments: &Value,
) -> Result<BTreeSet<String>, TnLlamaError> {
    let object = arguments
        .as_object()
        .filter(|object| exact_keys(object, &["data_hashes", "governance_hash"]))
        .ok_or_else(decrypt_keys_error)?;
    let (governance_hash, encrypted) = governed_hash_keys(core)?;
    if object.get("governance_hash").and_then(Value::as_str) != Some(governance_hash.as_str()) {
        return Err(decrypt_keys_error());
    }
    let hashes = object
        .get("data_hashes")
        .and_then(Value::as_array)
        .filter(|hashes| !hashes.is_empty())
        .ok_or_else(decrypt_keys_error)?;
    let count = hashes.len();
    let hashes = hashes
        .iter()
        .map(|hash| hash.as_str().ok_or_else(decrypt_keys_error))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if hashes.len() != count {
        return Err(decrypt_keys_error());
    }
    hashes
        .into_iter()
        .map(|hash| {
            encrypted
                .iter()
                .find(|(_, fields)| fields.values().any(|token| token == hash))
                .map(|(section, _)| section.clone())
                .ok_or_else(decrypt_keys_error)
        })
        .collect()
}

/// Encryption opens a whole group. The model receives only the fields it asked for.
fn retain_presented_fields(core: &mut SessionCore, arguments: &Value) {
    if core.governed.is_none() {
        return;
    }
    let presented = arguments["data_hashes"]
        .as_array()
        .expect("validated decrypt arguments")
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    let retained = core
        .opened_sections
        .keys()
        .map(|section| {
            let hashes = core.governed_request().object.envelope()[section]["field_hashes"]
                .as_object()
                .expect("native field hashes");
            let fields = hashes
                .iter()
                .filter(|(_, hash)| hash.as_str().is_some_and(|hash| presented.contains(hash)))
                .map(|(field, _)| field.clone())
                .collect::<BTreeSet<_>>();
            (section.clone(), fields)
        })
        .collect::<BTreeMap<_, _>>();
    for (section, value) in &mut core.opened_sections {
        if let Some(fields) = value.as_object_mut() {
            fields.retain(|field, _| retained[section].contains(field));
        }
    }
}

fn decrypt_keys_error() -> TnLlamaError {
    session_error(
        "tn_decrypt_keys_invalid",
        "decrypt_value requires the governance hash key and hash keys of this encrypted data",
    )
}

fn validate_section_selection_arguments(
    core: &SessionCore,
    arguments: &Value,
) -> Result<BTreeSet<String>, TnLlamaError> {
    let object = arguments
        .as_object()
        .filter(|object| exact_keys(object, &["sections"]))
        .ok_or_else(section_selection_error)?;
    let sections = object
        .get("sections")
        .and_then(Value::as_array)
        .filter(|sections| !sections.is_empty())
        .ok_or_else(section_selection_error)?;
    let selected = sections
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|name| !name.is_empty())
                .map(str::to_string)
                .ok_or_else(section_selection_error)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if selected.len() != sections.len() {
        return Err(section_selection_error());
    }
    let available = available_section_manifest(core)?;
    if selected.iter().all(|name| available.contains_key(name)) {
        Ok(selected)
    } else {
        Err(section_selection_error())
    }
}

fn exact_keys<const N: usize>(object: &Map<String, Value>, expected: &[&str; N]) -> bool {
    object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
}

fn section_selection_error() -> TnLlamaError {
    session_error(
        "tn_section_selection_invalid",
        "selected sections must be a nonempty unique subset of available configured sections",
    )
}

fn stored_call(call: &StoredCall) -> AcceptedCall<'_> {
    AcceptedCall {
        runtime: call.origin == CallOrigin::Runtime,
        id: &call.id,
        name: &call.name,
        arguments: &call.arguments,
    }
}

fn consume_outstanding(core: &mut SessionCore) {
    if let Some(outstanding) = core.outstanding.as_mut() {
        outstanding.lifecycle = PermitLifecycle::Consumed;
    }
    core.outstanding = None;
}

#[derive(Clone, Copy)]
enum FailedSink {
    None,
    Audit,
    Trace,
}

fn terminalize(
    core: &mut SessionCore,
    error: TnLlamaError,
    failed_sink: FailedSink,
) -> TnLlamaError {
    let before = core.state;
    core.state = State::Failed;
    if let Some(outstanding) = core.outstanding.as_mut() {
        outstanding.lifecycle = PermitLifecycle::Invalid;
    }
    core.outstanding = None;
    if let Some(admitted) = core.admitted.take() {
        let _ = admitted.abort();
    }
    if !matches!(failed_sink, FailedSink::Trace) {
        let _ = core.trace.append(SensitiveTraceEvent {
            run_id: &core.run_id,
            phase: before.phase(),
            kind: SensitiveTraceKind::Error,
            task_id: None,
            slot_id: None,
            request_json: None,
            rendered_prompt: None,
            runnable_manifest: None,
            raw_model_output: None,
            parsed_content: None,
            error_code: Some(error.code()),
        });
    }
    if !matches!(failed_sink, FailedSink::Audit) {
        let _ = append_audit(
            core,
            "terminal_error",
            before,
            State::Failed,
            before.phase(),
            None,
            None,
            "deny",
            Some(error.code()),
            AuditFacts::default(),
        );
    }
    error
}

#[allow(clippy::too_many_arguments)]
fn append_audit(
    core: &SessionCore,
    kind: &str,
    before: State,
    after: State,
    phase: Option<Phase>,
    task_id: Option<i64>,
    slot_id: Option<i32>,
    outcome: &str,
    error_code: Option<&str>,
    mut facts: AuditFacts,
) -> std::io::Result<()> {
    let mut event =
        AuditEvent::transition(before.as_str(), after.as_str(), core.row_hash(), outcome);
    event.kind = kind.to_string();
    event.request_digest = core.request_digest().to_string();
    event.llama_task_id = task_id;
    event.llama_slot_id = slot_id;
    event.error_code = error_code.map(str::to_string);
    facts.phase = phase;
    facts.turn_ordinal = core.outstanding.as_ref().map(|turn| turn.serial);
    if facts.model_request_digest.is_none() {
        facts.model_request_digest = core
            .outstanding
            .as_ref()
            .map(|turn| audit_digest(&turn.model_request_digest));
    }
    if facts.rendered_prompt_digest.is_none() {
        facts.rendered_prompt_digest = core
            .outstanding
            .as_ref()
            .and_then(|turn| turn.rendered_prompt_digest.as_deref())
            .map(audit_digest);
    }
    if facts.runnable_task_digest.is_none() {
        facts.runnable_task_digest = core
            .outstanding
            .as_ref()
            .and_then(|turn| turn.runnable_task_digest.as_deref())
            .map(audit_digest);
    }
    if facts.execution_identity.is_none() {
        facts.execution_identity =
            core.outstanding
                .as_ref()
                .and_then(|turn| match &turn.execution_identity {
                    Some(crate::ExecutionIdentity::Vllm(_)) => turn.execution_identity.clone(),
                    _ => None,
                });
    }
    event.facts = facts;
    core.audit.append(event).map(|_| ())
}

fn audit_digest(value: &str) -> AuditDigest {
    AuditDigest::new(value.to_string()).expect("runtime digest has the fixed sha256 shape")
}

impl SessionCore {
    fn admitted_request(&self) -> &AdmittedRequest {
        match self.admitted.as_ref().expect("active session is admitted") {
            AdmittedInput::LegacyChained(request) => request,
            AdmittedInput::GovernedObject(_) => unreachable!("legacy-only helper"),
        }
    }

    fn governed_request(&self) -> &crate::AcceptedGovernedRequest {
        match self.admitted.as_ref().expect("active session is admitted") {
            AdmittedInput::GovernedObject(request) => &request.request,
            AdmittedInput::LegacyChained(_) => unreachable!("governed-only helper"),
        }
    }

    fn row_hash(&self) -> &str {
        &self.row_hash
    }

    fn request_digest(&self) -> &str {
        &self.request_digest
    }
}

fn lock_core(core: &Arc<Mutex<SessionCore>>) -> Result<MutexGuard<'_, SessionCore>, TnLlamaError> {
    core.lock().map_err(|_| {
        session_error(
            "tn_session_state",
            "governed session state lock is unavailable",
        )
    })
}

fn lock_recover(core: &Arc<Mutex<SessionCore>>) -> MutexGuard<'_, SessionCore> {
    core.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
