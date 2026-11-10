//! Turn permits: one issued model turn, prepared, begun, and its result validated.

use super::*;

pub struct TurnPermit {
    pub(super) core: Arc<Mutex<SessionCore>>,
    pub(super) run_id: String,
    pub(super) serial: u64,
    pub(super) phase: Phase,
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
        let bytes = TurnBytes {
            request_json,
            rendered_prompt,
            runnable_manifest,
        };
        let mut core = lock_core(&self.core)?;
        let manifest_digest = match self.check_prepare(&core, &bytes) {
            Ok(digest) => digest,
            Err(error) => return Err(terminalize(&mut core, error, FailedSink::None)),
        };
        trace_turn(
            &mut core,
            self.phase,
            SensitiveTraceKind::TurnPrepared,
            (None, None),
            &bytes,
            "turn preparation trace append failed",
        )?;
        let outstanding = core.outstanding.as_mut().expect("validated outstanding");
        outstanding.rendered_prompt_digest = Some(rendered_prompt_digest(rendered_prompt));
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
        let execution = match &identity {
            crate::ExecutionIdentity::Llama { task_id, slot_id } => {
                (Some(*task_id), Some(*slot_id))
            }
            crate::ExecutionIdentity::Vllm(_) => (None, None),
        };
        let bytes = TurnBytes {
            request_json,
            rendered_prompt,
            runnable_manifest,
        };
        let mut core = lock_core(&self.core)?;
        if let Err(error) = self.check_begin(&core, &identity, &bytes) {
            return Err(terminalize(&mut core, error, FailedSink::None));
        }
        trace_turn(
            &mut core,
            self.phase,
            SensitiveTraceKind::TurnStarted,
            execution,
            &bytes,
            "turn begin trace append failed",
        )?;
        self.audit_begin(&mut core, &identity, execution)?;
        let outstanding = core.outstanding.as_mut().expect("validated outstanding");
        outstanding.execution_identity = Some(identity);
        outstanding.task_id = execution.0;
        outstanding.slot_id = execution.1;
        outstanding.lifecycle = PermitLifecycle::Begun;
        Ok(())
    }

    /// An issued permit's body is the Rust-issued bytes; returns the runnable manifest's digest.
    fn check_prepare(
        &self,
        core: &SessionCore,
        bytes: &TurnBytes<'_>,
    ) -> Result<String, TnLlamaError> {
        validate_identity(core, self)?;
        let outstanding = outstanding_turn(core)?;
        expect_lifecycle(outstanding.lifecycle, PermitLifecycle::Issued)?;
        if bytes.request_json != outstanding.request_json {
            return Err(session_error(
                "tn_turn_binding_mismatch",
                "prepared model body differs from the Rust-issued bytes",
            ));
        }
        core.execution_backend
            .digest(bytes.runnable_manifest, self.phase, outstanding.n_predict)
    }

    /// A prepared permit begins only on the prepared body, rendered prompt, and runnable manifest.
    fn check_begin(
        &self,
        core: &SessionCore,
        identity: &crate::ExecutionIdentity,
        bytes: &TurnBytes<'_>,
    ) -> Result<(), TnLlamaError> {
        validate_identity(core, self)?;
        core.execution_backend
            .validate_identity(identity, bytes.runnable_manifest)?;
        let outstanding = outstanding_turn(core)?;
        expect_lifecycle(outstanding.lifecycle, PermitLifecycle::Prepared)?;
        if bytes.request_json != outstanding.request_json {
            return Err(session_error(
                "tn_turn_binding_mismatch",
                "begun model body differs from the prepared bytes",
            ));
        }
        let prompt_digest = rendered_prompt_digest(bytes.rendered_prompt);
        let manifest_digest = core.execution_backend.digest(
            bytes.runnable_manifest,
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
    }

    /// Record the governance context the turn is bound to, then the authorized begin.
    fn audit_begin(
        &self,
        core: &mut SessionCore,
        identity: &crate::ExecutionIdentity,
        execution: (Option<i64>, Option<i32>),
    ) -> Result<(), TnLlamaError> {
        let mut bound = governance_identity_facts(core);
        bound.context_digest = Some(audit_digest(
            &core
                .outstanding
                .as_ref()
                .expect("validated outstanding")
                .context_digest,
        ));
        bound.execution_identity = vllm_identity(identity);
        let (task_id, slot_id) = execution;
        let phase = Some(self.phase);
        if append_audit(
            core,
            "governance_context_bound",
            core.state,
            core.state,
            phase,
            task_id,
            slot_id,
            "allow",
            None,
            bound,
        )
        .is_err()
        {
            return Err(audit_failed(
                core,
                "governance context binding audit append failed",
            ));
        }
        let authorized = AuditFacts {
            execution_identity: vllm_identity(identity),
            ..AuditFacts::default()
        };
        if append_audit(
            core,
            "turn_begin_authorized",
            core.state,
            core.state,
            phase,
            task_id,
            slot_id,
            "allow",
            None,
            authorized,
        )
        .is_err()
        {
            return Err(audit_failed(
                core,
                "turn begin authorization audit append failed",
            ));
        }
        Ok(())
    }
}

/// The turn as the model process presents it: body, rendered prompt, and runnable manifest.
struct TurnBytes<'a> {
    request_json: &'a [u8],
    rendered_prompt: &'a [u8],
    runnable_manifest: &'a [u8],
}

fn trace_turn(
    core: &mut SessionCore,
    phase: Phase,
    kind: SensitiveTraceKind,
    execution: (Option<i64>, Option<i32>),
    bytes: &TurnBytes<'_>,
    message: &'static str,
) -> Result<(), TnLlamaError> {
    let traced = core.trace.append(SensitiveTraceEvent {
        run_id: &core.run_id,
        phase: Some(phase),
        kind,
        task_id: execution.0,
        slot_id: execution.1,
        request_json: Some(bytes.request_json),
        rendered_prompt: Some(bytes.rendered_prompt),
        runnable_manifest: Some(bytes.runnable_manifest),
        raw_model_output: None,
        parsed_content: None,
        error_code: None,
    });
    if traced.is_err() {
        let error = session_error("tn_sensitive_trace_append_failed", message);
        return Err(terminalize(core, error, FailedSink::Trace));
    }
    Ok(())
}

/// The permit must be in `expected`; any other state names what already happened to it.
fn expect_lifecycle(
    lifecycle: PermitLifecycle,
    expected: PermitLifecycle,
) -> Result<(), TnLlamaError> {
    if lifecycle == expected {
        return Ok(());
    }
    Err(match lifecycle {
        PermitLifecycle::Issued => session_error(
            "tn_turn_not_prepared",
            "turn permit must be prepared before begin",
        ),
        PermitLifecycle::Prepared => session_error(
            "tn_turn_already_prepared",
            "turn permit was already prepared",
        ),
        PermitLifecycle::Begun => {
            session_error("tn_turn_already_begun", "turn permit was already begun")
        }
        PermitLifecycle::Consumed => {
            session_error("tn_turn_consumed", "turn permit was already consumed")
        }
        PermitLifecycle::Invalid => session_error("tn_session_state", "turn permit is invalid"),
    })
}

fn outstanding_turn(core: &SessionCore) -> Result<&OutstandingTurn, TnLlamaError> {
    core.outstanding
        .as_ref()
        .ok_or_else(|| session_error("tn_turn_consumed", "turn permit is no longer outstanding"))
}

/// The execution identity the audit records: only vLLM's; llama.cpp's is its task and slot.
fn vllm_identity(identity: &crate::ExecutionIdentity) -> Option<crate::ExecutionIdentity> {
    match identity {
        crate::ExecutionIdentity::Vllm(_) => Some(identity.clone()),
        _ => None,
    }
}

pub(super) fn validate_identity(
    core: &SessionCore,
    permit: &TurnPermit,
) -> Result<(), TnLlamaError> {
    if core.run_id != permit.run_id {
        return Err(session_error(
            "tn_turn_session_mismatch",
            "turn permit run ID does not match the session",
        ));
    }
    let outstanding = outstanding_turn(core)?;
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
pub(super) fn validate_begun(core: &SessionCore, permit: &TurnPermit) -> Result<(), TnLlamaError> {
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
pub(super) fn validate_native_call(
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
        Phase::SectionSelection => "decrypt_value",
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
    let arguments_value = crate::strict_json::parse_duplicate_safe_json(call.parsed_arguments)
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
            validate_decrypt_arguments(core, &arguments_value)?;
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

/// The begun turn's one native call, after its raw result is retained in the sensitive trace.
pub(super) fn accepted_call(
    core: &mut SessionCore,
    permit: &TurnPermit,
    result: &NativeToolResult<'_>,
) -> Result<StoredCall, TnLlamaError> {
    if let Err(error) = validate_begun(core, permit) {
        return Err(terminalize(core, error, FailedSink::None));
    }
    let traced = core.trace.append(SensitiveTraceEvent {
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
    });
    if traced.is_err() {
        let error = session_error(
            "tn_sensitive_trace_append_failed",
            "model-result trace append failed",
        );
        return Err(terminalize(core, error, FailedSink::Trace));
    }
    validate_native_call(core, permit.phase, result)
        .map_err(|error| terminalize(core, error, FailedSink::None))
}
