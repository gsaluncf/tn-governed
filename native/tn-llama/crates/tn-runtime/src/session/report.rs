//! Report emission: accepted markup, attribution, governed release, and the closed release.

use super::*;

pub(super) fn accept_report_emission(
    core: &mut SessionCore,
    phase: Phase,
    call: StoredCall,
    task_id: Option<i64>,
    slot_id: Option<i32>,
) -> Result<ActionOutcome, TnLlamaError> {
    let result = (|| {
        let html = parse_report_html(&call.arguments)?;
        validate_html_attributions(core, &html)?;
        let state = &core.governed;
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
    // Completion releases the session's admission capacity.
    core.admitted = None;
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
pub(super) fn audit_object_register(
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
pub(super) fn parse_report_html(arguments: &str) -> Result<String, TnLlamaError> {
    let value =
        crate::strict_json::parse_duplicate_safe_json(arguments.as_bytes()).map_err(|_| {
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
pub(super) fn validate_html_attributions(
    core: &SessionCore,
    html: &str,
) -> Result<(), TnLlamaError> {
    // Only the accepted markup reaches the attribution check, so nothing can hide it.
    let visible_text = crate::report_html::visible_report_text(html)?;
    for (section, rule) in &core.report_contract.section_rules {
        let Some(attribution) = &rule.required_attribution else {
            continue;
        };
        let attribution = crate::report_html::normalized(attribution);
        if core.selected_sections.contains(section) {
            if !visible_text.contains(&attribution) {
                return Err(session_error(
                    "tn_required_attribution_missing",
                    "report omitted a selected section's exact human-visible attribution",
                ));
            }
        } else if visible_text.contains(&attribution) || html.contains(attribution.as_str()) {
            return Err(session_error(
                "tn_unselected_attribution_present",
                "report carried attribution for an unselected section",
            ));
        }
    }
    Ok(())
}
