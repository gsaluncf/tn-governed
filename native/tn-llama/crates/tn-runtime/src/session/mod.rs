use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use serde_json::{Map, Value};

use crate::admission::AdmittedGovernedRequest;
use crate::audit::{AuditDigest, AuditEvent, AuditFacts, DecisionAudit};
use crate::client_trace::{ActionOutcome, ClientTraceEvent};
use crate::contract::ReportContract;
use crate::governance::VerifiedGovernance;
use crate::model_phase::Phase;
use crate::model_protocol::{
    decrypt_turn_body, governance_context_digest, model_request_digest, rendered_prompt_digest,
    session_error, AcceptedCall, NativeToolResult, ToolExchange,
};
use crate::sensitive_trace::{SensitiveTraceEvent, SensitiveTraceKind, SensitiveTraceSink};
use crate::tools::{RegisteredCall, ToolDispatcher};
use crate::TnLlamaError;

mod actions;
mod decrypt;
mod evidence;
mod permit;
mod report;

use actions::*;
use decrypt::*;
use evidence::*;
pub use permit::TurnPermit;
use permit::*;
use report::*;

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
    admitted: Option<AdmittedGovernedRequest>,
    governed: GovernedSessionState,
    report_contract: Arc<ReportContract>,
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
    client_trace: Vec<ClientTraceEvent>,
}

pub(crate) struct GovernedSessionState {
    pub input: Arc<crate::governed_input::GovernedInputRuntime>,
    pub output: Arc<crate::output_tn::GovernedOutputPublisher>,
    pub view: Option<tn_core::governed::GovernanceView>,
    /// The request object's admitted route: it and each object on the path to a carried group's holder.
    pub route: Option<tn_core::governed::AdmittedRoute>,
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

impl Session {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        run_id: String,
        execution_backend: crate::ExecutionBackend,
        admitted: AdmittedGovernedRequest,
        audit: Arc<dyn DecisionAudit>,
        trace: Arc<dyn SensitiveTraceSink>,
        report_contract: Arc<ReportContract>,
        tool_dispatcher: Arc<ToolDispatcher>,
        final_max_tokens: u32,
        governed: GovernedSessionState,
    ) -> Result<Self, TnLlamaError> {
        let row_hash = admitted.request.object.id().to_string();
        let request_digest = admitted.request.request_digest.clone();
        let user_content = admitted.request.messages[0].content.clone();
        let source_id = row_hash.clone();
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
                report_contract,
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
                Phase::SectionSelection => {
                    let (governance_hash, encrypted_data) = governed_hash_keys(&core)?;
                    decrypt_turn_body(
                        &core.user_content,
                        &encrypted_data,
                        &governance_hash,
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
        if matches!(permit.phase, Phase::GovernanceRead | Phase::CommitmentEcho) {
            return Err(session_error(
                "tn_turn_phase_mismatch",
                "reserved model phase cannot accept a result",
            ));
        }
        let mut core = lock_core(&self.core)?;
        if !Arc::ptr_eq(&self.core, &permit.core) {
            let error = session_error(
                "tn_turn_session_mismatch",
                "turn permit belongs to a different session",
            );
            return Err(terminalize(&mut core, error, FailedSink::None));
        }
        let call = accepted_call(&mut core, &permit, &result)?;
        match permit.phase {
            Phase::SectionSelection => accept_decrypt_call(&mut core, permit.phase, call),
            _ => accept_action(&mut core, Some(permit.phase), call),
        }
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
        core.admitted = None;
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let mut core = lock_recover(&self.core);
        core.admitted = None;
        if !matches!(core.state, State::Complete) {
            core.state = State::Failed;
        }
    }
}

impl SessionCore {
    fn governed_request(&self) -> &crate::AcceptedGovernedRequest {
        &self
            .admitted
            .as_ref()
            .expect("active session is admitted")
            .request
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
