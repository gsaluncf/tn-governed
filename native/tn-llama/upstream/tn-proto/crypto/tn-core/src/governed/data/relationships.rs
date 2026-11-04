//! Adding admitted policies, dataset bindings, and causal inputs to a working copy.
//! Each change is built on a candidate governance and applied only on success.
use super::{DataObject, Inclusion};
use crate::governed::contracts::merge_policies;
use crate::governed::dataset::merge_bindings;
use crate::governed::{invalid, AttachmentContext, DatasetSelection, Governance, SourceReference};
use crate::{Error, Result};
use std::collections::HashSet;

impl DataObject {
    /// Receipt has already verified this private accepted selection against the source.
    pub(crate) fn bind_selection(&mut self, selection: &DatasetSelection) -> Result<()> {
        let mut candidate = self.governance.clone();
        merge_bindings(&mut candidate, [selection.binding()])?;
        self.governance = candidate;
        self.changed();
        Ok(())
    }
    /// Add an authority-approved policy without replacing any existing contract.
    pub fn attach<F>(&mut self, authority: &str, policy: Governance, decide: F) -> Result<()>
    where
        F: FnOnce(&AttachmentContext<'_>) -> Result<bool>,
    {
        crate::trust::parse_ed25519_did_key(authority)
            .map_err(|_| invalid("attachment authority requires a DID"))?;
        let additional = policy.policies()?;
        let context = AttachmentContext {
            authority,
            data: self,
            policy: &policy,
        };
        if !decide(&context)? {
            return Err(Error::UseDenied {
                operation: "policy.attach".to_owned(),
            });
        }
        let mut candidate = self.governance.clone();
        merge_policies(&mut candidate, additional)?;
        self.governance = candidate;
        self.changed();
        Ok(())
    }
    /// Include another admitted input's causal references and every attached policy.
    /// Data assignment stays explicit; the additional source object remains available to its owner.
    pub fn include(&mut self, other: &Self) -> Result<()> {
        self.include_all([other.inclusion()?])
    }
    /// The contracts, dataset bindings and causal references this object contributes.
    pub fn inclusion(&self) -> Result<Inclusion> {
        Ok(Inclusion {
            policies: self.policies()?,
            bindings: self.dataset_bindings()?,
            sources: self.sources.clone(),
        })
    }
    /// Include several admitted inputs with one merge over their references.
    pub fn include_all(&mut self, inputs: impl IntoIterator<Item = Inclusion>) -> Result<()> {
        let mut candidate = self.governance.clone();
        let mut policies = Vec::new();
        let mut bindings = Vec::new();
        let mut known: HashSet<SourceReference> = self.sources.iter().cloned().collect();
        let mut sources = self.sources.clone();
        for input in inputs {
            policies.extend(input.policies);
            bindings.extend(input.bindings);
            for source in input.sources {
                if known.insert(source.clone()) {
                    sources.push(source);
                }
            }
        }
        merge_policies(&mut candidate, policies)?;
        merge_bindings(&mut candidate, bindings)?;
        self.governance = candidate;
        self.sources = sources;
        self.changed();
        Ok(())
    }
}
