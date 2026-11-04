//! Binding manifests: each value field's claims and the parent subjects it was computed from.
use std::collections::BTreeSet;
use std::sync::Arc;

use serde_json::{Map, Value};
use tn_core::governed::{GovernanceView, GovernedObject};

use super::is_value_object;
use crate::governed_input::{refused, AcceptedGovernedRequest, GovernedInputRuntime};
use crate::reference_runs::{parent_subjects, Subject};
use crate::TnLlamaError;

pub(super) struct Binding {
    pub(super) group: String,
    pub(super) field: String,
    pub(super) claims: Vec<String>,
    pub(super) parents: Vec<Subject>,
}

impl GovernedInputRuntime {
    /// Retained objects and this runtime's reader keys are fixed, so a manifest
    /// opened and verified for one use is the same for every later turn.
    pub(super) fn retained_manifest(
        &self,
        view: &GovernanceView,
        request: &AcceptedGovernedRequest,
    ) -> Result<Option<Arc<Map<String, Value>>>, TnLlamaError> {
        let key = (view.object().id().to_owned(), request.use_context.clone());
        let cached = self
            .manifests
            .lock()
            .map_err(|_| refused("tn_claim_manifest_invalid"))?
            .get(&key)
            .cloned();
        if let Some(found) = cached {
            return Ok(found);
        }
        let opened = self.open_manifest(view, request)?.map(Arc::new);
        if self.retained.contains_key(&key.0) {
            self.manifests
                .lock()
                .map_err(|_| refused("tn_claim_manifest_invalid"))?
                .insert(key, opened.clone());
        }
        Ok(opened)
    }

    fn open_manifest(
        &self,
        view: &GovernanceView,
        request: &AcceptedGovernedRequest,
    ) -> Result<Option<Map<String, Value>>, TnLlamaError> {
        if !view.object().group_names().contains(&"evidence") {
            return Ok(None);
        }
        let admitted = view
            .clone()
            .accept(request.use_context.clone(), ["evidence"], |ctx| {
                if !self.config.trusted_writers.contains(ctx.object().writer()) {
                    return Ok(false);
                }
                for policy in ctx.policies()? {
                    let Some(permission) = self.config.contracts.iter().find(|permission| {
                        Some(permission.revision_id.as_str()) == policy.revision_id()
                            && permission.allowed_uses.contains(&request.use_context)
                    }) else {
                        return Ok(false);
                    };
                    if policy
                        != self
                            .dag
                            .select(&permission.revision_id, &permission.scope, |_| Ok(true))?
                    {
                        return Ok(false);
                    }
                }
                Ok(true)
            })
            .map_err(|_| refused("tn_claim_manifest_access_denied"))?;
        let opened = self
            .reader
            .open(&admitted, ["evidence"])
            .map_err(|_| refused("tn_claim_manifest_invalid"))?;
        let Some(Value::Object(fields)) = opened.into_groups().remove("evidence") else {
            return Err(refused("tn_claim_manifest_invalid"));
        };
        Ok(Some(fields))
    }
}

pub(super) fn manifest_bindings(
    view: &GovernanceView,
    evidence: &Map<String, Value>,
    complete: bool,
) -> Result<Vec<Binding>, TnLlamaError> {
    let object = view.object();
    let Some(manifest) = evidence.get("manifest") else {
        if is_value_object(object) {
            return Err(refused("tn_claim_manifest_invalid"));
        }
        return Ok(Vec::new());
    };
    let group = match manifest.get("schema").and_then(Value::as_str) {
        Some("tn.primitive-bindings.v1" | "tn.primitive-batch.v1") => "values",
        Some("tn.string-bindings.v1") => "strings",
        _ if is_value_object(object) => return Err(refused("tn_claim_manifest_invalid")),
        _ => return Ok(Vec::new()),
    };
    // A source batch keeps one row per cell. Its cells have no parents or claims.
    let batch = manifest.get("schema").and_then(Value::as_str) == Some("tn.primitive-batch.v1");
    let fields = manifest
        .get(if batch { "cells" } else { "bindings" })
        .and_then(Value::as_object)
        .ok_or_else(|| refused("tn_claim_manifest_invalid"))?;
    if complete {
        check_complete(object, group, fields)?;
    }
    let references = view
        .governance()
        .source_references()
        .map_err(|_| refused("tn_claim_manifest_invalid"))?;
    let sources: BTreeSet<&str> = references
        .iter()
        .map(|reference| reference.object_id())
        .collect();
    fields
        .iter()
        .map(|(field, binding)| field_binding(object, group, field, binding, batch, &sources))
        .collect()
}

/// A root's manifest names exactly the fields its group's holder committed to.
fn check_complete(
    object: &GovernedObject,
    group: &str,
    fields: &Map<String, Value>,
) -> Result<(), TnLlamaError> {
    // The signed field hashes live with the object that holds the group, which a
    // successor may carry whole.
    let committed = object
        .holder(group)
        .ok_or_else(|| refused("tn_claim_manifest_invalid"))?
        .envelope()
        .get(group)
        .and_then(|block| block.get("field_hashes"))
        .and_then(Value::as_object)
        .ok_or_else(|| refused("tn_claim_manifest_invalid"))?;
    if fields.keys().collect::<BTreeSet<_>>() != committed.keys().collect::<BTreeSet<_>>() {
        return Err(refused("tn_claim_manifest_invalid"));
    }
    Ok(())
}

fn field_binding(
    object: &GovernedObject,
    group: &str,
    field: &str,
    binding: &Value,
    batch: bool,
    sources: &BTreeSet<&str>,
) -> Result<Binding, TnLlamaError> {
    if !has_field(object, group, field) {
        return Err(refused("tn_claim_manifest_invalid"));
    }
    if batch {
        return Ok(Binding {
            group: group.into(),
            field: field.into(),
            claims: Vec::new(),
            parents: Vec::new(),
        });
    }
    let claims: Vec<String> = serde_json::from_value(binding["claims"].clone())
        .map_err(|_| refused("tn_claim_manifest_invalid"))?;
    let parents =
        parent_subjects(&binding["parents"]).ok_or_else(|| refused("tn_claim_manifest_invalid"))?;
    if claims.iter().collect::<BTreeSet<_>>().len() != claims.len() {
        return Err(refused("tn_claim_manifest_invalid"));
    }
    if parents
        .iter()
        .any(|parent| !sources.contains(parent.object_id.as_str()))
    {
        return Err(refused("tn_claim_association_invalid"));
    }
    Ok(Binding {
        group: group.into(),
        field: field.into(),
        claims,
        parents,
    })
}

pub(super) fn has_field(object: &GovernedObject, group: &str, field: &str) -> bool {
    group != "tn.agents"
        && object
            .holder(group)
            .and_then(|holder| holder.envelope().get(group))
            .and_then(|block| block.get("field_hashes"))
            .and_then(Value::as_object)
            .is_some_and(|fields| fields.contains_key(field))
}
