//! Claim records: opened under their evidence contracts and tied to their original subjects.
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};
use tn_core::governed::{Governance, GovernedObject};

use super::manifest::has_field;
use super::{Bindings, Views};
use crate::governed_input::{refused, AcceptedGovernedRequest, GovernedInputRuntime};
use crate::reference_runs::Subject;
use crate::TnLlamaError;

const EVIDENCE_BODY_FIELDS: [&str; 12] = [
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

impl GovernedInputRuntime {
    /// Each cited claim, opened and checked against the publication that introduced it.
    pub(super) fn cited_claims(
        &self,
        request: &AcceptedGovernedRequest,
        required: BTreeMap<String, BTreeSet<String>>,
        views: &Views,
        bindings: &Bindings,
    ) -> Result<Vec<Value>, TnLlamaError> {
        let records = self.claim_records_by_id()?;
        let mut claims = Vec::new();
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
            if !introduced(record, &id, &subjects, views, bindings)
                || cited_by.iter().any(|root| {
                    subjects.iter().any(|subject| {
                        !reaches(
                            root,
                            &subject.object_id,
                            views,
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
        Ok(claims)
    }

    pub(super) fn claim_records_by_id(
        &self,
    ) -> Result<BTreeMap<String, GovernedObject>, TnLlamaError> {
        let mut records = BTreeMap::new();
        for wire in &self.claim_records {
            let record =
                GovernedObject::parse(wire).map_err(|_| refused("tn_claim_record_invalid"))?;
            if records.insert(record.id().to_owned(), record).is_some() {
                return Err(refused("tn_claim_record_invalid"));
            }
        }
        Ok(records)
    }

    /// Add every ancestor that a root's signed source references reach, within the limits.
    pub(super) fn claim_ancestry(
        &self,
        roots: &[String],
        views: &mut Views,
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

    pub(super) fn open_claim(
        &self,
        record: &GovernedObject,
        request: &AcceptedGovernedRequest,
    ) -> Result<(Map<String, Value>, Governance), TnLlamaError> {
        let (body, governance) = self.open_evidence(record, request)?;
        if !is_claim_body(&body) {
            return Err(refused("tn_claim_record_invalid"));
        }
        Ok((body, governance))
    }

    pub(super) fn open_evidence(
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
        let body = fields
            .get("record")
            .and_then(Value::as_object)
            .ok_or_else(|| refused("tn_claim_record_invalid"))?;
        if fields.len() != 1 || !is_evidence_body(body) {
            return Err(refused("tn_claim_record_invalid"));
        }
        Ok((body.clone(), governance))
    }
}

fn is_evidence_body(body: &Map<String, Value>) -> bool {
    body.len() == EVIDENCE_BODY_FIELDS.len()
        && EVIDENCE_BODY_FIELDS
            .iter()
            .all(|field| body.contains_key(*field))
        && ["context_id", "call_id", "application", "purpose"]
            .iter()
            .all(|field| {
                body.get(*field)
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.is_empty())
            })
        && body
            .get("sequence")
            .and_then(Value::as_u64)
            .is_some_and(|sequence| sequence != 0)
        && body.get("schema") == Some(&json!("tn.string-evidence.v1"))
}

fn is_claim_body(body: &Map<String, Value>) -> bool {
    body.get("kind") == Some(&json!("Claim"))
        && body.get("operation") == Some(&json!("attest"))
        && body
            .get("details")
            .and_then(|details| details.get("statement"))
            .and_then(Value::as_str)
            .is_some_and(|statement| !statement.trim().is_empty())
}

/// A claim's introducing publication cites its original subjects and bears the issuer's signature.
fn introduced(
    record: &GovernedObject,
    id: &str,
    subjects: &[Subject],
    views: &Views,
    bindings: &Bindings,
) -> bool {
    bindings.iter().any(|(publication, items)| {
        views[publication].object().writer() == record.writer()
            && items.iter().any(|binding| {
                binding.claims.iter().any(|claim| claim == id) && binding.parents == subjects
            })
    })
}

fn reaches(start: &str, target: &str, views: &Views, limit: usize) -> bool {
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
