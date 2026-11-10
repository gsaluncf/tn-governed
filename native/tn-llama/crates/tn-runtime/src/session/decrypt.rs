//! The decrypt turn: the hash keys offered to the model and the groups its call opens.

use super::*;

/// Open the groups the model's validated decrypt call presented the hash keys of.
pub(super) fn accept_decrypt_call(
    core: &mut SessionCore,
    phase: Phase,
    call: StoredCall,
) -> Result<ActionOutcome, TnLlamaError> {
    let arguments = crate::strict_json::parse_duplicate_safe_json(call.arguments.as_bytes())
        .expect("native call arguments were validated");
    let selected_sections = match validate_decrypt_arguments(core, &arguments) {
        Ok(sections) => sections,
        Err(error) => return Err(terminalize(core, error, FailedSink::None)),
    };
    let outcome = apply_section_selection(core, Some(phase), call, selected_sections)?;
    retain_presented_fields(core, &arguments);
    Ok(outcome)
}

pub(super) fn apply_section_selection(
    core: &mut SessionCore,
    phase: Option<Phase>,
    call: StoredCall,
    selected_sections: BTreeSet<String>,
) -> Result<ActionOutcome, TnLlamaError> {
    let governance_hash = called_governance_hash(&call);
    let route = core
        .governed
        .route
        .as_ref()
        .expect("route admitted with governance");
    // The key was paired with these groups when the call was validated; an opening
    // failure here keeps its own code.
    let data = match core
        .governed
        .input
        .open(route, &selected_sections, &governance_hash)
    {
        Ok(data) => data,
        Err(error) => return Err(terminalize(core, error, FailedSink::None)),
    };
    let opened_sections = data
        .groups()
        .iter()
        .map(|(name, fields)| (name.clone(), Value::Object(fields.clone())))
        .collect();
    core.governed.data = Some(data);
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
/// The configured sections the request object holds or carries, before admission.
pub(super) fn offered_sections(core: &SessionCore) -> Result<BTreeSet<String>, TnLlamaError> {
    let held = core.governed_request().object.held_groups();
    let offered: BTreeSet<String> = core
        .report_contract
        .allowed_input_sections
        .iter()
        .filter(|name| held.contains(name.as_str()))
        .cloned()
        .collect();
    if offered.is_empty() {
        return Err(session_error(
            "tn_section_selection_invalid",
            "admitted row contains no configured input sections",
        ));
    }
    Ok(offered)
}
/// The field names of `group` in the envelope of the object that holds it.
pub(super) fn field_names(object: &tn_core::governed::GovernedObject, group: &str) -> Vec<String> {
    object.envelope()[group]["field_hashes"]
        .as_object()
        .expect("native field hashes")
        .keys()
        .cloned()
        .collect()
}
/// The admitted route of a governed session.
pub(super) fn admitted_route(
    core: &SessionCore,
) -> Result<&tn_core::governed::AdmittedRoute, TnLlamaError> {
    core.governed
        .route
        .as_ref()
        .ok_or_else(|| session_error("tn_session_state", "admitted route is unavailable"))
}
pub(super) fn available_section_manifest(
    core: &SessionCore,
) -> Result<BTreeMap<String, Vec<String>>, TnLlamaError> {
    let encrypted: BTreeMap<String, Vec<String>> = admitted_route(core)?
        .stops()
        .flat_map(|(admitted, supplied)| {
            supplied
                .iter()
                .map(move |group| (group.clone(), field_names(admitted.object(), group)))
        })
        .collect();
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
/// The hash key of the request object's governance and, per offered group, the hash
/// keys of its encrypted data. A group the request object carries also names the hash
/// key of its holder's governance, which the model passes to decrypt it.
pub(super) fn governed_hash_keys(
    core: &SessionCore,
) -> Result<
    (
        String,
        BTreeMap<String, crate::model_protocol::DecryptOffer>,
    ),
    TnLlamaError,
> {
    let state = &core.governed;
    let route = admitted_route(core)?;
    let request_id = core.governed_request().object.id();
    let (direct, _) = route.stops().next().expect("a route starts at its source");
    let governance_hash = state.input.supplier_hash_key(direct)?;
    let mut offers = BTreeMap::new();
    for section in available_section_manifest(core)?.into_keys() {
        let supplier = route
            .supplier(&section)
            .ok_or_else(|| session_error("tn_session_state", "data hash keys are unavailable"))?;
        let hashes =
            serde_json::from_value(supplier.object().envelope()[&section]["field_hashes"].clone())
                .map_err(|_| session_error("tn_session_state", "data hash keys are unavailable"))?;
        let carried = supplier.object().id() != request_id;
        let governance_hash = if carried {
            Some(state.input.supplier_hash_key(supplier)?)
        } else {
            None
        };
        offers.insert(
            section,
            crate::model_protocol::DecryptOffer {
                governance_hash,
                hashes,
            },
        );
    }
    Ok((governance_hash, offers))
}
/// The governance hash key exactly as the model's validated decrypt call passed it.
pub(super) fn called_governance_hash(call: &StoredCall) -> String {
    crate::strict_json::parse_duplicate_safe_json(call.arguments.as_bytes())
        .ok()
        .and_then(|arguments| arguments["governance_hash"].as_str().map(str::to_owned))
        .unwrap_or_default()
}
pub(super) fn validate_decrypt_arguments(
    core: &SessionCore,
    arguments: &Value,
) -> Result<BTreeSet<String>, TnLlamaError> {
    let object = arguments
        .as_object()
        .filter(|object| exact_keys(object, &["data_hashes", "governance_hash"]))
        .ok_or_else(decrypt_keys_error)?;
    // The supplied key must be the key of the object governing every selected group.
    // Native opening checks it again against the governance it decrypts.
    let supplied = object
        .get("governance_hash")
        .and_then(Value::as_str)
        .ok_or_else(decrypt_keys_error)?;
    let (direct_key, offers) = governed_hash_keys(core)?;
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
            // A field hash alone does not name an object: pair it with the key.
            offers
                .iter()
                .find(|(_, offer)| {
                    offer.governance_hash.as_deref().unwrap_or(&direct_key) == supplied
                        && offer.hashes.values().any(|token| token == hash)
                })
                .map(|(section, _)| section.clone())
                .ok_or_else(decrypt_keys_error)
        })
        .collect()
}
/// Encryption opens a whole group. The model receives only the fields it asked for.
pub(super) fn retain_presented_fields(core: &mut SessionCore, arguments: &Value) {
    let presented = arguments["data_hashes"]
        .as_array()
        .expect("validated decrypt arguments")
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    let route = admitted_route(core).expect("route admitted with governance");
    let retained = core
        .opened_sections
        .keys()
        .map(|section| {
            let holder = route
                .supplier(section)
                .expect("opened groups are supplied")
                .object();
            let hashes = holder.envelope()[section]["field_hashes"]
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
pub(super) fn decrypt_keys_error() -> TnLlamaError {
    session_error(
        "tn_decrypt_keys_invalid",
        "decrypt_value requires the governance hash key and hash keys of this encrypted data",
    )
}
pub(super) fn exact_keys<const N: usize>(
    object: &Map<String, Value>,
    expected: &[&str; N],
) -> bool {
    object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
}
