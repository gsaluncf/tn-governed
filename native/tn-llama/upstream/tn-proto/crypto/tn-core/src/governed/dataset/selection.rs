//! Receipt against one accepted edition record and one allowed use.
use std::collections::BTreeSet;
use std::sync::Arc;

use super::bindings::check_binding_addition;
use super::catalog::AcceptedEdition;
use super::edition::validate_groups;
use super::{invalid, DatasetBinding, DatasetEdition};
use crate::governed::contracts::base_contract;
use crate::governed::{AdmissionContext, Governance, GovernanceView, GovernedObject, UseContext};
use crate::{Error, Result};

pub(super) fn exact_contracts(carried: &[Governance], expected: &[Governance]) -> Result<()> {
    if carried.len() != expected.len() {
        return Err(invalid(
            "source must carry exactly the selected edition's complete contract set",
        ));
    }
    let mut identities = BTreeSet::new();
    for policy in carried {
        let id = policy
            .revision_id()
            .ok_or_else(|| invalid("selected source contract requires a policy revision"))?;
        if !identities.insert(id)
            || !expected
                .iter()
                .any(|candidate| base_contract(candidate) == base_contract(policy))
        {
            return Err(invalid("source contract must exactly match the accepted revision, including all machine rules"));
        }
    }
    Ok(())
}

/// Native accepted state pinned to one signed record and one allowed-use tuple.
/// It has no public constructor or deserializer; only catalog selection creates it.
#[derive(Debug, Clone)]
pub struct DatasetSelection {
    pub(super) accepted: Arc<AcceptedEdition>,
    pub(super) use_context: UseContext,
}

impl DatasetSelection {
    /// Accepted signed record retained by this selection.
    pub fn record(&self) -> &DatasetEdition {
        &self.accepted.edition
    }
    /// Exact use accepted at selection time.
    pub fn use_context(&self) -> &UseContext {
        &self.use_context
    }
    /// Origin declaration to install only after strict source receipt succeeds.
    pub fn binding(&self) -> DatasetBinding {
        self.record().binding()
    }
    /// Exact source publication selected.
    pub fn source_object_id(&self) -> &str {
        self.record().source_object_id()
    }
    /// Exact signed edition record selected.
    pub fn edition_record_id(&self) -> &str {
        self.record().id()
    }

    /// Verify identity, groups, use, and the complete contracts before business opening.
    pub fn verify_source(
        &self,
        view: &GovernanceView,
        use_context: &UseContext,
        groups: &[String],
    ) -> Result<()> {
        self.verify(view.object(), view.governance(), use_context, groups)
    }

    /// Verify the strict admission context without exposing mutable accepted state.
    pub fn verify_context(&self, context: &AdmissionContext<'_>) -> Result<()> {
        let use_context = context
            .use_context()
            .ok_or_else(|| invalid("dataset selection requires a complete use context"))?;
        let groups = context
            .groups()
            .ok_or_else(|| invalid("dataset selection requires pinned business groups"))?;
        self.verify(context.object(), context.governance(), use_context, groups)
    }

    fn verify(
        &self,
        object: &GovernedObject,
        governance: &Governance,
        use_context: &UseContext,
        groups: &[String],
    ) -> Result<()> {
        if use_context != &self.use_context {
            return Err(Error::UseDenied {
                operation: use_context.operation().to_owned(),
            });
        }
        self.verify_source_identity(object)?;
        self.verify_source_groups(object, groups)?;
        exact_contracts(&governance.policies()?, &self.accepted.policies)?;
        // Receipt installs the selection after opening. Check that insertion can
        // succeed now, while the business groups are still ciphertext.
        check_binding_addition(&governance.dataset_bindings()?, &self.binding())?;
        Ok(())
    }

    /// The source is the selected record's exact publication, signer, and type.
    fn verify_source_identity(&self, object: &GovernedObject) -> Result<()> {
        let record = self.record();
        if object.id() != record.source_object_id()
            || object.writer() != record.source_writer()
            || object.object_type() != record.source_type()
        {
            return Err(invalid(
                "received publication must match the selected source identity, writer and type",
            ));
        }
        Ok(())
    }

    /// The source holds every declared group, and the edition supplies every requested one.
    fn verify_source_groups(&self, object: &GovernedObject, groups: &[String]) -> Result<()> {
        validate_groups(groups)?;
        let declared = self.record().source_groups();
        let held = object.group_names();
        if declared.iter().any(|name| !held.contains(&name.as_str())) {
            return Err(invalid(
                "every group declared by the edition must occur in its exact source publication",
            ));
        }
        if groups.iter().any(|name| !declared.contains(name) || !held.contains(&name.as_str())) {
            return Err(invalid(
                "requested groups must be supplied by the selected edition",
            ));
        }
        Ok(())
    }
}
