//! Selected plaintext, with the admission it was opened under.
use std::collections::BTreeMap;

use serde_json::Value;

use super::AdmittedObject;
use crate::governed::{Governance, GovernedDraft, GovernedObject, SourceReference, UseContext, GOVERNANCE_GROUP};
use crate::Result;

/// Selected plaintext with its accepted contract and original signed source.
#[derive(Clone)]
pub struct OpenedObject {
    pub(super) admitted: AdmittedObject,
    pub(super) groups: BTreeMap<String, Value>,
}

impl OpenedObject {
    /// The admission these groups were opened under.
    pub(in crate::governed) fn admitted(&self) -> &AdmittedObject {
        &self.admitted
    }
    /// Complete use accepted before opening these groups, when the strict path was used.
    pub fn use_context(&self) -> Option<&UseContext> {
        self.admitted.use_context()
    }
    /// Application operation for which these source groups were opened.
    pub fn operation(&self) -> &str {
        self.admitted.operation()
    }
    /// Typed causal reference for this admitted input.
    pub fn source_reference(&self) -> Result<SourceReference> {
        SourceReference::from_opened(self)
    }
    /// Selected business plaintext, separated by group.
    pub fn groups(&self) -> &BTreeMap<String, Value> {
        &self.groups
    }
    /// The selected plaintext, without a copy.
    pub fn into_groups(self) -> BTreeMap<String, Value> {
        self.groups
    }
    /// Accepted contract carried with the plaintext.
    pub fn governance(&self) -> &Governance {
        self.admitted.governance()
    }
    /// Complete original signed object, including unselected ciphertext.
    pub fn object(&self) -> &GovernedObject {
        self.admitted.object()
    }
    /// Business groups remaining encrypted in this view.
    pub fn hidden_groups(&self) -> Vec<&str> {
        self.object()
            .group_names()
            .into_iter()
            .filter(|name| *name != GOVERNANCE_GROUP && !self.groups.contains_key(*name))
            .collect()
    }

    /// Start a derivative with the continuing source contract and lineage. A
    /// successor under another contract goes through a working copy, which keeps
    /// this source's policies and dataset bindings.
    pub fn derive(&self, object_type: &str) -> Result<GovernedDraft> {
        GovernedDraft::new(object_type, self.governance().clone())?
            .with_source_lineage(&[self.source_reference()?])
    }
}
