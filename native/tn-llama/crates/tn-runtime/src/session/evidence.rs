//! Session evidence: audit events, the client trace, and terminal failure.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn push_client_trace(
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
pub(super) fn consume_outstanding(core: &mut SessionCore) {
    if let Some(outstanding) = core.outstanding.as_mut() {
        outstanding.lifecycle = PermitLifecycle::Consumed;
    }
    core.outstanding = None;
}
#[derive(Clone, Copy)]
pub(super) enum FailedSink {
    None,
    Audit,
    Trace,
}
pub(super) fn terminalize(
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
    core.admitted = None;
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
/// The terminal error for an audit sink that failed to record `message`'s event.
pub(super) fn audit_failed(core: &mut SessionCore, message: &'static str) -> TnLlamaError {
    terminalize(
        core,
        session_error("tn_audit_append_failed", message),
        FailedSink::Audit,
    )
}
#[allow(clippy::too_many_arguments)]
pub(super) fn append_audit(
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
pub(super) fn audit_digest(value: &str) -> AuditDigest {
    AuditDigest::new(value.to_string()).expect("runtime digest has the fixed sha256 shape")
}
