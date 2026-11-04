//! Governed actions: admission, the decision context, protected tools, and later turns.

use super::*;

pub(super) fn accept_action(
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
    accept_native_tool(core, phase, call, task_id, slot_id)
}
pub(super) fn available_action_tools(core: &SessionCore) -> Result<Vec<Value>, TnLlamaError> {
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
            Ok(spec.native_model_tool())
        })
        .collect()
}
pub(super) fn advance_runtime_actions(core: &mut SessionCore) -> Result<(), TnLlamaError> {
    let result = (|| {
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
pub(super) fn selected_values(core: &SessionCore) -> Result<BTreeMap<String, Value>, TnLlamaError> {
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
pub(super) fn required_attributions(core: &SessionCore) -> Vec<String> {
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
pub(super) fn required_tools(core: &SessionCore) -> BTreeSet<String> {
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
pub(super) fn governance_identity_facts(core: &SessionCore) -> AuditFacts {
    AuditFacts {
        governance_context_protocol: Some("tn.llama.governance-context.v1".into()),
        source_object_id: Some(core.row_hash.clone()),
        ..AuditFacts::default()
    }
}
pub(super) fn admit_governance(core: &mut SessionCore) -> Result<(), TnLlamaError> {
    let result = offered_sections(core).and_then(|groups| {
        core.governed
            .input
            .governance(core.governed_request(), &groups)
    });
    let (view, governance, route) =
        result.map_err(|error| terminalize(core, error, FailedSink::None))?;
    core.governed.view = Some(view);
    core.governed.route = Some(route);
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
pub(super) fn model_governance(
    core: &mut SessionCore,
) -> Result<BTreeMap<String, Value>, TnLlamaError> {
    let state = &core.governed;
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
    core.governed.context = Some((tools, context.clone()));
    Ok(context)
}
pub(super) fn governed_action_request(
    core: &SessionCore,
    governance_context: &BTreeMap<String, Value>,
) -> Result<Vec<u8>, TnLlamaError> {
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
    let decrypt_call = core
        .selection_call
        .as_ref()
        .ok_or_else(|| session_error("tn_session_state", "decrypt call history is unavailable"))?;
    crate::model_protocol::governed_object_action_body(
        &core.user_content,
        &selected_values(core)?,
        &governance_hash,
        stored_call(decrypt_call),
        governance_context,
        core.governed.input.report_policy.as_ref(),
        &required_attributions(core),
        core.governed_request().object.id(),
        &core.report_contract.operation,
        tools,
        &exchanges,
        core.final_max_tokens,
    )
}
pub(super) fn accept_native_tool(
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
    let state = &core.governed;
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
    core.governed.tools.push(receipt.publication);
    core.governed_tool_exchanges.push(StoredToolExchange {
        call,
        result: receipt_json,
    });
    consume_outstanding(core);
    Ok(ActionOutcome::Continue)
}
pub(super) fn stored_call(call: &StoredCall) -> AcceptedCall<'_> {
    AcceptedCall {
        runtime: call.origin == CallOrigin::Runtime,
        id: &call.id,
        name: &call.name,
        arguments: &call.arguments,
    }
}
