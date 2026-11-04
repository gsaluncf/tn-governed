//! Verified rule meaning and attributable claims supplied at each model decision.
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use serde_json::{json, Value};
use tn_core::governed::{GovernanceView, GovernedObject};

use crate::governed_input::{refused, AcceptedGovernedRequest, GovernedInputRuntime};
use crate::model_protocol::governance_presentation;
use crate::output_tn::GovernedPublication;
use crate::reference_runs::Subject;
use crate::TnLlamaError;

mod claims;
mod manifest;

use manifest::{has_field, Binding};

type Views = BTreeMap<String, GovernanceView>;
type Bindings = BTreeMap<String, Vec<Binding>>;

impl GovernedInputRuntime {
    pub fn decision_context(
        &self,
        request: &AcceptedGovernedRequest,
        source: &GovernanceView,
        tools: &[GovernedPublication],
    ) -> Result<BTreeMap<String, Value>, TnLlamaError> {
        let mut views = self.bound_views(request, source, tools)?;
        let (sources, root_ids) = self.verify_roots(source, tools, &mut views)?;
        let mut bindings = self.root_bindings(request, tools, &views, &root_ids)?;
        let required = required_claims(&root_ids, &bindings);
        if root_ids
            .iter()
            .any(|id| bindings.get(id).is_some_and(|items| !items.is_empty()))
        {
            self.claim_ancestry(&root_ids, &mut views)?;
            self.ancestor_bindings(request, &views, &mut bindings)?;
            check_associations(&views, &bindings)?;
        }
        let claims = if required.is_empty() {
            Vec::new()
        } else {
            self.cited_claims(request, required, &views, &bindings)?
        };
        Ok(BTreeMap::from([
            ("schema".into(), json!("tn.llama.decision-context.v1")),
            ("use".into(), json!(request.use_context)),
            ("destination".into(), json!(request.destination)),
            ("sources".into(), json!(sources)),
            ("claims".into(), json!(claims)),
        ]))
    }

    /// The request's source and each tool publication, once each, keyed by object id.
    fn bound_views(
        &self,
        request: &AcceptedGovernedRequest,
        source: &GovernanceView,
        tools: &[GovernedPublication],
    ) -> Result<Views, TnLlamaError> {
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
        Ok(views)
    }

    /// Verify each root's lineage and add its ancestors; returns each root's context and id.
    fn verify_roots(
        &self,
        source: &GovernanceView,
        tools: &[GovernedPublication],
        views: &mut Views,
    ) -> Result<(Vec<Value>, Vec<String>), TnLlamaError> {
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
                    let retained = self
                        .retained
                        .get(id)
                        .ok_or_else(|| refused("tn_decision_context_lineage_invalid"))?;
                    views.insert(id.clone(), retained.clone());
                }
            }
            root_ids.push(view.object().id().to_owned());
            sources.push(source_context(view)?);
        }
        Ok((sources, root_ids))
    }

    /// Each object's manifest bindings; a root primitive or string must have them.
    fn root_bindings(
        &self,
        request: &AcceptedGovernedRequest,
        tools: &[GovernedPublication],
        views: &Views,
        root_ids: &[String],
    ) -> Result<Bindings, TnLlamaError> {
        let mut bindings = BTreeMap::new();
        for (id, view) in views {
            let evidence = if let Some(tool) = tools.iter().find(|tool| tool.object.id() == id) {
                tool.data.groups().get("evidence").cloned().map(Arc::new)
            } else {
                self.retained_manifest(view, request)?
            };
            if let Some(fields) = evidence {
                bindings.insert(
                    id.clone(),
                    manifest::manifest_bindings(view, &fields, root_ids.contains(id))?,
                );
            } else if root_ids.contains(id) && is_value_object(view.object()) {
                return Err(refused("tn_claim_manifest_invalid"));
            }
        }
        Ok(bindings)
    }

    /// The bindings of the ancestors the claim walk added.
    fn ancestor_bindings(
        &self,
        request: &AcceptedGovernedRequest,
        views: &Views,
        bindings: &mut Bindings,
    ) -> Result<(), TnLlamaError> {
        for (id, view) in views {
            if !bindings.contains_key(id) {
                if let Some(fields) = self.retained_manifest(view, request)? {
                    bindings.insert(
                        id.clone(),
                        manifest::manifest_bindings(view, &fields, false)?,
                    );
                }
            }
        }
        Ok(())
    }
}

/// Each claim a root's bindings cite, with the roots that cite it.
fn required_claims(root_ids: &[String], bindings: &Bindings) -> BTreeMap<String, BTreeSet<String>> {
    let mut required: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for id in root_ids {
        for binding in bindings.get(id).into_iter().flatten() {
            for claim in &binding.claims {
                required
                    .entry(claim.clone())
                    .or_default()
                    .insert(id.clone());
            }
        }
    }
    required
}

/// Every binding's parents exist, have their own bindings, and pass their claims on.
fn check_associations(views: &Views, bindings: &Bindings) -> Result<(), TnLlamaError> {
    let by_field: HashMap<(&str, &str, &str), &Binding> = bindings
        .iter()
        .flat_map(|(id, items)| {
            items.iter().map(move |item| {
                (
                    (id.as_str(), item.group.as_str(), item.field.as_str()),
                    item,
                )
            })
        })
        .collect();
    for (id, items) in bindings {
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
                check_parent(views, bindings, &by_field, binding, parent)?;
            }
        }
    }
    Ok(())
}

fn check_parent(
    views: &Views,
    bindings: &Bindings,
    by_field: &HashMap<(&str, &str, &str), &Binding>,
    binding: &Binding,
    parent: &Subject,
) -> Result<(), TnLlamaError> {
    if views
        .get(&parent.object_id)
        .is_none_or(|view| !has_field(view.object(), &parent.group, &parent.field))
    {
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
        && is_value_object(views[&parent.object_id].object())
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
    Ok(())
}

/// Primitive and string objects always carry a binding manifest.
fn is_value_object(object: &GovernedObject) -> bool {
    matches!(
        object.object_type(),
        "experiment.primitive" | "experiment.string"
    )
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
