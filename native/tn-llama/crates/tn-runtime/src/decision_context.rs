//! Verified rule meaning and attributable claims supplied at each model decision.
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use serde_json::{json, Map, Value};
use tn_core::governed::{Governance, GovernanceView, GovernedObject};

use crate::governed_input::{refused, AcceptedGovernedRequest, GovernedInputRuntime};
use crate::model_protocol::governance_presentation;
use crate::output_tn::GovernedPublication;
use crate::reference_runs::{parent_subjects, Subject};
use crate::TnLlamaError;

struct Binding {
    group: String,
    field: String,
    claims: Vec<String>,
    parents: Vec<Subject>,
}

impl GovernedInputRuntime {
    pub fn decision_context(
        &self,
        request: &AcceptedGovernedRequest,
        source: &GovernanceView,
        tools: &[GovernedPublication],
    ) -> Result<BTreeMap<String, Value>, TnLlamaError> {
        if request.object.id() != source.object().id()
            || request.use_context != self.config.use_context
            || !self.config.destinations.contains(&request.destination)
        {
            return Err(refused("tn_decision_context_binding_invalid"));
        }
        let mut views = BTreeMap::from([(source.object().id().to_owned(), source.clone())]);
        for tool in tools {
            if tool.object.id() != tool.view.object().id()
                || views
                    .insert(tool.object.id().to_owned(), tool.view.clone())
                    .is_some()
            {
                return Err(refused("tn_decision_context_binding_invalid"));
            }
        }
        let roots = std::iter::once(source).chain(tools.iter().map(|tool| &tool.view));
        let mut sources = Vec::new();
        let mut root_ids = Vec::new();
        for view in roots {
            let lineage = self
                .lineage
                .verify(view, &self.catalog, &self.dag, |id| {
                    views
                        .get(id)
                        .or_else(|| self.retained.get(id))
                        .cloned()
                        .ok_or_else(|| {
                            tn_core::Error::InvalidConfig("missing decision ancestor".into())
                        })
                })
                .map_err(|_| refused("tn_decision_context_lineage_invalid"))?;
            for id in lineage.object_ids() {
                if !views.contains_key(id) {
                    views.insert(
                        id.clone(),
                        self.retained
                            .get(id)
                            .ok_or_else(|| refused("tn_decision_context_lineage_invalid"))?
                            .clone(),
                    );
                }
            }
            root_ids.push(view.object().id().to_owned());
            sources.push(source_context(view)?);
        }

        let mut bindings = BTreeMap::new();
        for (id, view) in &views {
            let evidence = if let Some(tool) = tools.iter().find(|tool| tool.object.id() == id) {
                tool.data.groups().get("evidence").cloned().map(Arc::new)
            } else {
                self.retained_manifest(view, request)?
            };
            if let Some(fields) = evidence {
                bindings.insert(
                    id.clone(),
                    manifest_bindings(view, &fields, root_ids.contains(id))?,
                );
            } else if root_ids.contains(id)
                && matches!(
                    view.object().object_type(),
                    "experiment.primitive" | "experiment.string"
                )
            {
                return Err(refused("tn_claim_manifest_invalid"));
            }
        }
        let mut required: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for id in &root_ids {
            for binding in bindings.get(id).into_iter().flatten() {
                for claim in &binding.claims {
                    required
                        .entry(claim.clone())
                        .or_default()
                        .insert(id.clone());
                }
            }
        }
        if root_ids
            .iter()
            .any(|id| bindings.get(id).is_some_and(|items| !items.is_empty()))
        {
            self.claim_ancestry(&root_ids, &mut views)?;
            for (id, view) in &views {
                if !bindings.contains_key(id) {
                    if let Some(fields) = self.retained_manifest(view, request)? {
                        bindings.insert(id.clone(), manifest_bindings(view, &fields, false)?);
                    }
                }
            }
            let by_field: HashMap<(&str, &str, &str), &Binding> = bindings
                .iter()
                .flat_map(|(id, items)| {
                    items.iter().map(move |item| {
                        ((id.as_str(), item.group.as_str(), item.field.as_str()), item)
                    })
                })
                .collect();
            for (id, items) in &bindings {
                let references = views[id]
                    .governance()
                    .source_references()
                    .map_err(|_| refused("tn_claim_association_invalid"))?;
                for binding in items {
                    if binding.parents.is_empty()
                        && references.iter().any(|reference| {
                            bindings
                                .get(reference.object_id())
                                .is_some_and(|parent| !parent.is_empty())
                        })
                    {
                        return Err(refused("tn_claim_association_invalid"));
                    }
                    for parent in &binding.parents {
                        if views.get(&parent.object_id).is_none_or(|view| {
                            !has_field(view.object(), &parent.group, &parent.field)
                        }) {
                            return Err(refused("tn_claim_subject_invalid"));
                        }
                        let parent_binding = by_field
                            .get(&(
                                parent.object_id.as_str(),
                                parent.group.as_str(),
                                parent.field.as_str(),
                            ))
                            .copied();
                        if bindings.contains_key(&parent.object_id)
                            && parent_binding.is_none()
                            && matches!(
                                views[&parent.object_id].object().object_type(),
                                "experiment.primitive" | "experiment.string"
                            )
                        {
                            return Err(refused("tn_claim_manifest_invalid"));
                        }
                        if parent_binding.is_some_and(|parent| {
                            parent
                                .claims
                                .iter()
                                .any(|claim| !binding.claims.contains(claim))
                        }) {
                            return Err(refused("tn_claim_association_invalid"));
                        }
                    }
                }
            }
        }
        let mut claims = Vec::new();
        if !required.is_empty() {
            let mut records = BTreeMap::new();
            for wire in &self.claim_records {
                let record =
                    GovernedObject::parse(wire).map_err(|_| refused("tn_claim_record_invalid"))?;
                if records.insert(record.id().to_owned(), record).is_some() {
                    return Err(refused("tn_claim_record_invalid"));
                }
            }
            for (id, cited_by) in required {
                let record = records
                    .get(&id)
                    .ok_or_else(|| refused("tn_claim_record_missing"))?;
                let (body, governance) = self.open_claim(record, request)?;
                let subjects: Vec<Subject> = serde_json::from_value(body["inputs"].clone())
                    .map_err(|_| refused("tn_claim_subject_invalid"))?;
                if subjects.is_empty()
                    || subjects.iter().any(|subject| {
                        views.get(&subject.object_id).is_none_or(|view| {
                            !has_field(view.object(), &subject.group, &subject.field)
                        })
                    })
                {
                    return Err(refused("tn_claim_subject_invalid"));
                }
                // A claim's introducing publication must cite its original
                // subjects and bear the same issuer's signature.
                let introduced = bindings.iter().any(|(publication, items)| {
                    views[publication].object().writer() == record.writer()
                        && items.iter().any(|binding| {
                            binding.claims.contains(&id) && binding.parents == subjects
                        })
                });
                if !introduced
                    || cited_by.iter().any(|root| {
                        subjects.iter().any(|subject| {
                            !reaches(
                                root,
                                &subject.object_id,
                                &views,
                                self.config.lineage_max_objects,
                            )
                        })
                    })
                {
                    return Err(refused("tn_claim_association_invalid"));
                }
                claims.push(json!({
                    "record_id":id, "issuer":record.writer(),
                    "governed_by":governance.governed_by(), "governance":governance.fields(),
                    "statement":body["details"]["statement"],
                    "original_subjects":body["inputs"], "source_object_ids":cited_by,
                }));
            }
        }
        Ok(BTreeMap::from([
            ("schema".into(), json!("tn.llama.decision-context.v1")),
            ("use".into(), json!(request.use_context)),
            ("destination".into(), json!(request.destination)),
            ("sources".into(), json!(sources)),
            ("claims".into(), json!(claims)),
        ]))
    }

    fn claim_ancestry(
        &self,
        roots: &[String],
        views: &mut BTreeMap<String, GovernanceView>,
    ) -> Result<(), TnLlamaError> {
        let mut pending: Vec<_> = roots.iter().map(|id| (id.clone(), 0)).collect();
        let mut visited = BTreeSet::new();
        while let Some((id, depth)) = pending.pop() {
            if depth > self.config.lineage_max_depth
                || views.len() > self.config.lineage_max_objects
            {
                return Err(refused("tn_claim_ancestry_limit"));
            }
            if !visited.insert(id.clone()) {
                continue;
            }
            let references = views[&id]
                .governance()
                .source_references()
                .map_err(|_| refused("tn_claim_association_invalid"))?;
            for reference in references {
                let parent = views
                    .get(reference.object_id())
                    .or_else(|| self.retained.get(reference.object_id()))
                    .ok_or_else(|| refused("tn_claim_subject_missing"))?;
                if !reference.references_with_policy(parent.object(), parent.governance())
                    || !reference
                        .groups()
                        .iter()
                        .all(|group| parent.object().group_names().contains(&group.as_str()))
                {
                    return Err(refused("tn_claim_association_invalid"));
                }
                let parent = parent.clone();
                views.insert(reference.object_id().to_owned(), parent);
                pending.push((reference.object_id().to_owned(), depth + 1));
            }
        }
        Ok(())
    }

    /// Retained objects and this runtime's reader keys are fixed, so a manifest
    /// opened and verified for one use is the same for every later turn.
    fn retained_manifest(
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
        self.verifier
            .verify_native_group(view.object(), "evidence", &fields)?;
        Ok(Some(fields))
    }

    fn open_claim(
        &self,
        record: &GovernedObject,
        request: &AcceptedGovernedRequest,
    ) -> Result<(Map<String, Value>, Governance), TnLlamaError> {
        if record.object_type() != "experiment.evidence"
            || !self.config.trusted_writers.contains(record.writer())
        {
            return Err(refused("tn_claim_issuer_denied"));
        }
        let view = self
            .reader
            .governance(record)
            .map_err(|_| refused("tn_claim_record_invalid"))?;
        self.verifier
            .verify_native_group(record, "tn.agents", view.governance().fields())?;
        let governance = view.governance().clone();
        let admitted = view
            .accept(request.use_context.clone(), ["evidence"], |ctx| {
                Ok(ctx.policies()?.iter().all(|policy| {
                    self.config.evidence_contracts.iter().any(|grant| {
                        self.config.authority_writers.contains(&grant.governed_by)
                            && grant.governed_by == policy.governed_by()
                            && grant.fields == *policy.fields()
                            && grant.allowed_uses.contains(&request.use_context)
                    })
                }))
            })
            .map_err(|_| refused("tn_claim_access_denied"))?;
        let opened = self
            .reader
            .open(&admitted, ["evidence"])
            .map_err(|_| refused("tn_claim_record_invalid"))?;
        let fields = opened.groups()["evidence"]
            .as_object()
            .ok_or_else(|| refused("tn_claim_record_invalid"))?;
        self.verifier
            .verify_native_group(record, "evidence", fields)?;
        let body = fields
            .get("record")
            .and_then(Value::as_object)
            .ok_or_else(|| refused("tn_claim_record_invalid"))?;
        let required = [
            "schema",
            "context_id",
            "sequence",
            "previous",
            "kind",
            "call_id",
            "application",
            "purpose",
            "operation",
            "inputs",
            "destination",
            "details",
        ];
        if fields.len() != 1
            || body.len() != required.len()
            || required.iter().any(|field| !body.contains_key(*field))
            || ["context_id", "call_id", "application", "purpose"]
                .iter()
                .any(|field| {
                    body.get(*field)
                        .and_then(Value::as_str)
                        .is_none_or(str::is_empty)
                })
            || body
                .get("sequence")
                .and_then(Value::as_u64)
                .is_none_or(|sequence| sequence == 0)
            || body.get("schema") != Some(&json!("tn.string-evidence.v1"))
            || body.get("kind") != Some(&json!("Claim"))
            || body.get("operation") != Some(&json!("attest"))
            || body
                .get("details")
                .and_then(|details| details.get("statement"))
                .and_then(Value::as_str)
                .is_none_or(|statement| statement.trim().is_empty())
        {
            return Err(refused("tn_claim_record_invalid"));
        }
        Ok((body.clone(), governance))
    }
}

fn source_context(view: &GovernanceView) -> Result<Value, TnLlamaError> {
    let fields = view.governance().fields().clone().into_iter().collect();
    let commitments =
        serde_json::from_value(view.object().envelope()["tn.agents"]["field_hashes"].clone())
            .map_err(|_| refused("tn_decision_context_binding_invalid"))?;
    Ok(json!({
        "object_id":view.object().id(), "writer":view.object().writer(),
        "governed_by":view.governance().governed_by(),
        "governance":governance_presentation(&fields, &commitments, view.object().id())?,
    }))
}

fn manifest_bindings(
    view: &GovernanceView,
    evidence: &Map<String, Value>,
    complete: bool,
) -> Result<Vec<Binding>, TnLlamaError> {
    let object = view.object();
    let Some(manifest) = evidence.get("manifest") else {
        if matches!(
            object.object_type(),
            "experiment.primitive" | "experiment.string"
        ) {
            return Err(refused("tn_claim_manifest_invalid"));
        }
        return Ok(Vec::new());
    };
    let group = match manifest.get("schema").and_then(Value::as_str) {
        Some("tn.primitive-bindings.v1" | "tn.primitive-batch.v1") => "values",
        Some("tn.string-bindings.v1") => "strings",
        _ if matches!(
            object.object_type(),
            "experiment.primitive" | "experiment.string"
        ) =>
        {
            return Err(refused("tn_claim_manifest_invalid"))
        }
        _ => return Ok(Vec::new()),
    };
    // A source batch keeps one row per cell. Its cells have no parents or claims.
    let batch = manifest.get("schema").and_then(Value::as_str) == Some("tn.primitive-batch.v1");
    let fields = manifest
        .get(if batch { "cells" } else { "bindings" })
        .and_then(Value::as_object)
        .ok_or_else(|| refused("tn_claim_manifest_invalid"))?;
    if complete {
        let committed = object
            .envelope()
            .get(group)
            .and_then(|block| block.get("field_hashes"))
            .and_then(Value::as_object)
            .ok_or_else(|| refused("tn_claim_manifest_invalid"))?;
        if fields.keys().collect::<BTreeSet<_>>() != committed.keys().collect::<BTreeSet<_>>() {
            return Err(refused("tn_claim_manifest_invalid"));
        }
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
        .map(|(field, binding)| {
            if !has_field(object, group, field) {
                return Err(refused("tn_claim_manifest_invalid"));
            }
            if batch {
                return Ok(Binding {
                    group: group.into(),
                    field: field.clone(),
                    claims: Vec::new(),
                    parents: Vec::new(),
                });
            }
            let claims: Vec<String> = serde_json::from_value(binding["claims"].clone())
                .map_err(|_| refused("tn_claim_manifest_invalid"))?;
            let parents = parent_subjects(&binding["parents"])
                .ok_or_else(|| refused("tn_claim_manifest_invalid"))?;
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
                field: field.clone(),
                claims,
                parents,
            })
        })
        .collect()
}

fn has_field(object: &GovernedObject, group: &str, field: &str) -> bool {
    group != "tn.agents"
        && object
            .envelope()
            .get(group)
            .and_then(|block| block.get("field_hashes"))
            .and_then(Value::as_object)
            .is_some_and(|fields| fields.contains_key(field))
}

fn reaches(
    start: &str,
    target: &str,
    views: &BTreeMap<String, GovernanceView>,
    limit: usize,
) -> bool {
    let mut pending = vec![start.to_owned()];
    let mut visited = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if id == target {
            return true;
        }
        if !visited.insert(id.clone()) {
            continue;
        }
        if visited.len() > limit {
            return false;
        }
        let Some(view) = views.get(&id) else {
            return false;
        };
        let Ok(references) = view.governance().source_references() else {
            return false;
        };
        for reference in references {
            if let Some(parent) = views.get(reference.object_id()) {
                if !reference.references_with_policy(parent.object(), parent.governance()) {
                    return false;
                }
                pending.push(reference.object_id().to_owned());
            }
        }
    }
    false
}
