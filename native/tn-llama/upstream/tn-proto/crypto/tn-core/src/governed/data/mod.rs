//! Mutable data with retained contracts and immutable signed versions.
//!
//! This module holds the working state, its constructors, and its accessors.
//! [`edit`] changes plaintext, [`relationships`] adds policies, dataset bindings,
//! and causal inputs, and [`release`] drafts and signs successors.
mod edit;
mod relationships;
mod release;
#[cfg(test)]
mod tests;

use super::carried::unopened_groups;
use super::{
    invalid, validate_name, DatasetBinding, Governance, GovernedObject, OpenedObject,
    SourceReference,
};
use crate::Result;
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// What one admitted input adds when another object includes it.
pub struct Inclusion {
    policies: Vec<Governance>,
    bindings: Vec<DatasetBinding>,
    sources: Vec<SourceReference>,
}

/// A mutable working object. Policy attachment is append-only; releases retain snapshots.
#[derive(Clone)]
pub struct DataObject {
    object_type: String,
    governance: Governance,
    groups: BTreeMap<String, Map<String, Value>>,
    /// Unopened business groups, each with the whole object that holds and binds it.
    opaque: BTreeMap<String, GovernedObject>,
    /// The holders in `opaque`, in the breadth-first order receipt resolved them.
    holders: Vec<GovernedObject>,
    manifest: Option<String>,
    sources: Vec<SourceReference>,
    history: Vec<GovernedObject>,
    revision: u64,
    unreleased_changes: bool,
    register_error: Option<String>,
}

impl DataObject {
    /// Originate a mutable object with its required contract and first business group.
    pub fn new(
        object_type: &str,
        policy: Governance,
        group: &str,
        fields: impl Serialize,
    ) -> Result<Self> {
        Self::new_with_groups(object_type, policy, [(group, fields)])
    }
    /// Originate all business groups together before creating a signed snapshot.
    /// An empty collection, duplicate names, or reserved governance group is refused.
    pub fn new_with_groups<I, S, V>(
        object_type: &str,
        policy: Governance,
        groups: I,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = (S, V)>,
        S: AsRef<str>,
        V: Serialize,
    {
        validate_name(object_type)?;
        policy.policies()?;
        policy.dataset_bindings()?;
        let sources = policy.source_references()?;
        let mut data = Self {
            object_type: object_type.to_owned(),
            governance: policy,
            groups: BTreeMap::new(),
            opaque: BTreeMap::new(),
            holders: Vec::new(),
            manifest: None,
            sources,
            history: Vec::new(),
            revision: 0,
            unreleased_changes: true,
            register_error: None,
        };
        for (name, fields) in groups {
            let name = name.as_ref();
            if data.groups.contains_key(name) {
                return Err(invalid(format!("duplicate business group {name:?}")));
            }
            data.set_group(name, fields)?;
        }
        if data.groups.is_empty() {
            return Err(invalid("creation requires at least one business group"));
        }
        Ok(data)
    }
    /// Use admitted selected plaintext while retaining every unopened source group.
    pub fn from_opened(opened: OpenedObject) -> Result<Self> {
        let source = SourceReference::from_opened(&opened)?;
        let groups = opened
            .groups()
            .iter()
            .map(|(name, value)| {
                value
                    .as_object()
                    .cloned()
                    .map(|fields| (name.clone(), fields))
                    .ok_or_else(|| invalid("business group must be an object"))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let (opaque, holders) = unopened_groups(opened.object(), &groups);
        let manifest = opened
            .object()
            .manifest_group()
            .filter(|name| groups.contains_key(*name))
            .map(str::to_owned);
        Ok(Self {
            object_type: opened.object().object_type().to_owned(),
            governance: opened.governance().clone(),
            groups,
            opaque,
            holders,
            manifest,
            sources: vec![source],
            history: vec![opened.object().clone()],
            revision: 0,
            unreleased_changes: false,
            register_error: None,
        })
    }
    /// A routed receipt: the direct input's working copy, with each group opened from
    /// the object that carries it. The direct input stays the only causal input; each
    /// carrying object's policies and dataset bindings join the governance.
    pub(crate) fn from_route(direct: OpenedObject, carried: Vec<OpenedObject>) -> Result<Self> {
        let mut data = Self::from_opened(direct)?;
        for opened in carried {
            let governance = opened.governance();
            let inclusion = Inclusion {
                policies: governance.policies()?,
                bindings: governance.dataset_bindings()?,
                sources: Vec::new(),
            };
            data.include_all([inclusion])?;
            for (name, value) in opened.into_groups() {
                let fields = value
                    .as_object()
                    .cloned()
                    .ok_or_else(|| invalid("business group must be an object"))?;
                data.opaque.remove(&name);
                data.groups.insert(name, fields);
            }
        }
        // Receipt is not a mutation of the received data.
        data.revision = 0;
        data.unreleased_changes = false;
        Ok(data)
    }
    /// Exact selected dataset origins retained through mutation and inclusion.
    pub fn dataset_bindings(&self) -> Result<Vec<DatasetBinding>> {
        self.governance.dataset_bindings()
    }
    /// Current object type.
    pub fn object_type(&self) -> &str {
        &self.object_type
    }
    /// Primary governance; callers cannot replace or remove it.
    pub fn governance(&self) -> &Governance {
        &self.governance
    }
    /// Primary and additional policy contracts.
    pub fn policies(&self) -> Result<Vec<Governance>> {
        self.governance.policies()
    }
    /// Current selected plaintext groups.
    pub fn groups(&self) -> &BTreeMap<String, Map<String, Value>> {
        &self.groups
    }
    /// Selected plaintext for one group.
    pub fn group(&self, name: &str) -> Option<&Map<String, Value>> {
        self.groups.get(name)
    }
    /// Groups retained as original ciphertext.
    pub fn hidden_groups(&self) -> Vec<&str> {
        self.opaque.keys().map(String::as_str).collect()
    }
    /// The manifest group named for the next release, if any.
    pub fn manifest(&self) -> Option<&str> {
        self.manifest.as_deref()
    }
    /// Causal inputs of the next release.
    pub fn sources(&self) -> &[SourceReference] {
        &self.sources
    }
    /// Latest sealed snapshot, suitable for exact-byte retry.
    pub fn snapshot(&self) -> Option<&GovernedObject> {
        self.history.last()
    }
    /// Retained signed versions, in local observation/release order.
    pub fn history(&self) -> &[GovernedObject] {
        &self.history
    }
    /// Working-state generation for callback/concurrency checks.
    pub fn revision(&self) -> u64 {
        self.revision
    }
    /// Whether a successful mutation occurred since the latest signed snapshot.
    /// A newly constructed unsaved object is also pending. Refused operations
    /// preserve this state; successful release records the current state.
    /// This describes local working data, independently of delivery or database commit.
    pub fn has_unreleased_changes(&self) -> bool {
        self.unreleased_changes
    }
    /// Most recent optional register I/O error; the sealed snapshot remains available.
    pub fn register_error(&self) -> Option<&str> {
        self.register_error.as_deref()
    }
    #[cfg(feature = "fs")]
    pub(crate) fn set_register_error(&mut self, error: Option<String>) {
        self.register_error = error;
    }
    fn changed(&mut self) {
        self.revision = self.revision.wrapping_add(1);
        self.unreleased_changes = true;
    }
    /// Inspect a detached snapshot of the current working state.
    pub fn inspect(&self) -> Self {
        self.clone()
    }
    /// Forward only a current signed publication, never stale working data.
    pub fn forward(&self) -> Result<&[u8]> {
        if self.has_unreleased_changes() {
            return Err(invalid("release working changes before forwarding"));
        }
        Ok(self
            .snapshot()
            .ok_or_else(|| invalid("object has no signed publication"))?
            .forward())
    }
}
