//! Admission of a current value, its signed claims, and receipts for completed actions.
use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};
use tn_core::governed::{Governance, GovernanceView, GovernedObject};

use super::manifest::check_complete;
use crate::governed_input::{refused, AcceptedGovernedRequest, GovernedInputRuntime};
use crate::output_tn::GovernedPublication;
use crate::reference_runs::Subject;
use crate::TnLlamaError;

impl GovernedInputRuntime {
    pub(super) fn carried_decision_context(
        &self,
        request: &AcceptedGovernedRequest,
        source: &GovernanceView,
        tools: &[GovernedPublication],
    ) -> Result<BTreeMap<String, Value>, TnLlamaError> {
        let (claim_ids, action_ids) = self.carried_citations(source, request)?;
        let claims = self.claim_records_by_id()?;
        let mut presentation = Vec::new();
        for id in claim_ids {
            let record = claims
                .get(&id)
                .ok_or_else(|| refused("tn_claim_record_missing"))?;
            let (body, governance) = self.open_claim(record, request)?;
            let subjects: Vec<Subject> = serde_json::from_value(body["inputs"].clone())
                .map_err(|_| refused("tn_claim_subject_invalid"))?;
            if subjects.is_empty()
                || subjects.iter().any(|s| {
                    s.group.trim().is_empty()
                        || s.group == "tn.agents"
                        || s.field.trim().is_empty()
                        || s.object_id.trim().is_empty()
                })
            {
                return Err(refused("tn_claim_subject_invalid"));
            }
            presentation.push(json!({
                "record_id":id, "issuer":record.writer(), "governed_by":governance.governed_by(),
                "governance":rule_fields(&governance), "statement":body["details"]["statement"],
                "original_subjects":body["inputs"], "source_object_ids":[source.object().id()],
            }));
        }
        self.verify_action_evidence(request, action_ids)?;
        let sources = std::iter::once(source)
            .chain(tools.iter().map(|tool| &tool.view))
            .map(|view| {
                json!({
                    "object_id":view.object().id(), "writer":view.object().writer(),
                    "governed_by":view.governance().governed_by(),
                    "governance":rule_fields(view.governance()),
                })
            })
            .collect::<Vec<_>>();
        Ok(BTreeMap::from([
            ("schema".into(), json!("tn.llama.decision-context.v1")),
            ("use".into(), json!(request.use_context)),
            ("destination".into(), json!(request.destination)),
            ("sources".into(), json!(sources)),
            ("claims".into(), json!(presentation)),
        ]))
    }

    fn carried_citations(
        &self,
        source: &GovernanceView,
        request: &AcceptedGovernedRequest,
    ) -> Result<(BTreeSet<String>, BTreeSet<String>), TnLlamaError> {
        let invalid = || refused("tn_claim_manifest_invalid");
        let primitive = super::is_value_object(source.object());
        let evidence = self.retained_manifest(source, request)?;
        let Some(evidence) = evidence else {
            return if primitive {
                Err(invalid())
            } else {
                Ok(Default::default())
            };
        };
        let manifest = evidence.get("manifest").ok_or_else(invalid)?;
        let fields = manifest["bindings"].as_object().ok_or_else(invalid)?;
        let group = match manifest["schema"].as_str() {
            // Primitive handoffs select one standalone field.
            Some("tn.primitive-policy.v1") if primitive && fields.len() == 1 => "values",
            Some("tn.governed-fields.v1") if !primitive => {
                let groups = source
                    .object()
                    .group_names()
                    .into_iter()
                    .filter(|group| !matches!(*group, "tn.agents" | "evidence"))
                    .collect::<Vec<_>>();
                let [group] = groups.as_slice() else {
                    return Err(invalid());
                };
                if fields
                    .values()
                    .any(|binding| binding["group"].as_str() != Some(*group))
                {
                    return Err(invalid());
                }
                *group
            }
            _ => return Err(invalid()),
        };
        check_complete(source.object(), group, fields)?;
        let mut claims = BTreeSet::new();
        let mut actions = BTreeSet::new();
        for binding in fields.values() {
            claims.extend(cited_ids(&binding["claims"])?);
            actions.extend(cited_ids(&binding["actions"])?);
        }
        Ok((claims, actions))
    }

    fn verify_action_evidence(
        &self,
        request: &AcceptedGovernedRequest,
        actions: BTreeSet<String>,
    ) -> Result<(), TnLlamaError> {
        let mut records = BTreeMap::new();
        for wire in &self.action_records {
            let record =
                GovernedObject::parse(wire).map_err(|_| refused("tn_action_record_invalid"))?;
            if records.insert(record.id().to_owned(), record).is_some() {
                return Err(refused("tn_action_record_invalid"));
            }
        }
        for id in actions {
            let record = records
                .get(&id)
                .ok_or_else(|| refused("tn_action_record_missing"))?;
            let (body, _) = self.open_evidence(record, request)?;
            let details = &body["details"];
            let obligations = details["obligations"]
                .as_array()
                .ok_or_else(|| refused("tn_action_record_invalid"))?;
            let discharged = details["discharged"]
                .as_array()
                .ok_or_else(|| refused("tn_action_record_invalid"))?;
            if body["kind"] != "Decision"
                || body["schema"] != "tn.string-evidence.v1"
                || details["permitted"] != true
                || obligations.len() != discharged.len()
                || obligations.is_empty()
            {
                return Err(refused("tn_action_record_invalid"));
            }
            for (obligation, step) in obligations.iter().zip(discharged) {
                let receipt = step["evidence"]
                    .as_str()
                    .filter(|s| !s.trim().is_empty())
                    .ok_or_else(|| refused("tn_action_record_invalid"))?;
                if obligation.as_str().is_none_or(|s| s.trim().is_empty())
                    || step["satisfied"] != true
                    || step["obligation"] != *obligation
                {
                    return Err(refused("tn_action_record_invalid"));
                }
                if receipt.starts_with("sha256:") {
                    let evidence = records
                        .get(receipt)
                        .ok_or_else(|| refused("tn_action_record_missing"))?;
                    let (receipt_body, _) = self.open_evidence(evidence, request)?;
                    if obligation == "monitor"
                        && (evidence.writer() != record.writer()
                            || !monitor_matches(&body, &receipt_body))
                    {
                        return Err(refused("tn_action_record_invalid"));
                    }
                } else if obligation == "monitor" {
                    return Err(refused("tn_action_record_invalid"));
                }
            }
        }
        Ok(())
    }
}

/// A monitoring receipt attests to this operation before the permit was issued.
fn monitor_matches(decision: &Map<String, Value>, receipt: &Map<String, Value>) -> bool {
    receipt["kind"] == "Monitor"
        && receipt["sequence"].as_u64() < decision["sequence"].as_u64()
        && decision["details"]["actor"]
            .as_str()
            .is_some_and(|actor| !actor.trim().is_empty())
        && receipt["details"]["actor"] == decision["details"]["actor"]
        && [
            "context_id",
            "application",
            "purpose",
            "operation",
            "inputs",
            "destination",
        ]
        .iter()
        .all(|name| receipt[*name] == decision[*name])
}

/// The model sees authenticated policy text, machine rules, and extension conditions.
fn rule_fields(governance: &Governance) -> BTreeMap<&str, &Value> {
    governance
        .fields()
        .iter()
        .filter(|(name, _)| !matches!(name.as_str(), "source_lineage" | "dataset_bindings"))
        .map(|(name, value)| (name.as_str(), value))
        .collect()
}

fn cited_ids(value: &Value) -> Result<Vec<String>, TnLlamaError> {
    let ids: Vec<String> =
        serde_json::from_value(value.clone()).map_err(|_| refused("tn_claim_manifest_invalid"))?;
    if ids.iter().collect::<BTreeSet<_>>().len() != ids.len() {
        return Err(refused("tn_claim_manifest_invalid"));
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monitor_receipt_must_precede_and_identify_the_permitted_action() {
        let decision = json!({
            "kind":"Decision", "sequence":3, "context_id":"context", "application":"analytics",
            "purpose":"internal", "operation":"upper", "inputs":[{"field":"a"}], "destination":null,
            "details":{"actor":"analyst"},
        });
        let mut receipt = decision.clone();
        receipt["kind"] = json!("Monitor");
        receipt["sequence"] = json!(2);
        let matches = |body: &Value| {
            monitor_matches(decision.as_object().unwrap(), body.as_object().unwrap())
        };
        assert!(matches(&receipt));
        for (field, value) in [
            ("kind", json!("Claim")),
            ("sequence", json!(3)),
            ("context_id", json!("other")),
            ("application", json!("other")),
            ("purpose", json!("other")),
            ("operation", json!("lower")),
            ("inputs", json!([])),
            ("destination", json!("elsewhere")),
            ("details", json!({"actor":"other"})),
        ] {
            let mut changed = receipt.clone();
            changed[field] = value;
            assert!(!matches(&changed), "{field}");
        }
    }
}
