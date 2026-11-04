//! The append-only catalog of authority-approved edition records.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::bindings::same_bindings;
use super::selection::exact_contracts;
use super::{invalid, label, ContractBinding, DatasetBinding, DatasetEdition, DatasetSelection};
use crate::governed::contracts::base_contract;
use crate::governed::revision::validate_revision_id;
use crate::governed::{AdmissionContext, Governance, PolicyDag, UseContext};
use crate::{Error, Result};

#[derive(Debug, Clone)]
pub(super) struct AcceptedEdition {
    pub(super) edition: DatasetEdition,
    pub(super) policies: Vec<Governance>,
}

/// A record that passed validation and authority against one catalog state.
#[derive(Debug)]
pub struct PreparedEdition {
    accepted: AcceptedEdition,
    catalog: u64,
    revision: u64,
}

/// Append-only catalog of authority-approved exact edition records.
///
/// `identity` names one catalog and the copies made from it; `revision` counts
/// its commits. Together they are the state a preparation was checked against.
#[derive(Debug, Clone)]
pub struct DatasetCatalog {
    records: BTreeMap<String, Arc<AcceptedEdition>>,
    identity: u64,
    revision: u64,
}

impl Default for DatasetCatalog {
    fn default() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        Self {
            records: BTreeMap::new(),
            identity: NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            revision: 0,
        }
    }
}

impl DatasetCatalog {
    /// Start an empty catalog.
    pub fn new() -> Self {
        Self::default()
    }
    /// Number of accepted immutable records.
    pub fn len(&self) -> usize {
        self.records.len()
    }
    /// Whether no records have been accepted.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    /// Resolve only an exact already accepted record identity.
    pub fn get(&self, record_id: &str) -> Option<&DatasetEdition> {
        self.records.get(record_id).map(|record| &record.edition)
    }

    /// Resolve all required revisions, then atomically apply catalog authority admission.
    /// Duplicate identities are errors, even when the signed content is identical.
    pub fn admit<F>(&mut self, edition: DatasetEdition, dag: &PolicyDag, authorize: F) -> Result<()>
    where
        F: FnOnce(&DatasetEdition) -> Result<bool>,
    {
        let prepared = self.prepare(edition, dag, authorize)?;
        self.commit(prepared)
    }

    /// Run every admission check without changing accepted state.
    pub fn prepare<F>(
        &self,
        edition: DatasetEdition,
        dag: &PolicyDag,
        authorize: F,
    ) -> Result<PreparedEdition>
    where
        F: FnOnce(&DatasetEdition) -> Result<bool>,
    {
        edition.body.validate()?;
        if self.records.contains_key(edition.id()) {
            return Err(invalid(
                "edition record already admitted; accepted catalog is immutable",
            ));
        }
        let policies = selected_policies(edition.contracts(), dag)?;
        if !authorize(&edition)? {
            return Err(Error::UseDenied {
                operation: "dataset.admit".to_owned(),
            });
        }
        Ok(PreparedEdition {
            accepted: AcceptedEdition { edition, policies },
            catalog: self.identity,
            revision: self.revision,
        })
    }

    /// Add a record prepared against this exact catalog state. A preparation made
    /// against another catalog, or before any later commit, is refused unchanged.
    pub fn commit(&mut self, prepared: PreparedEdition) -> Result<()> {
        if prepared.catalog != self.identity || prepared.revision != self.revision {
            return Err(invalid(
                "dataset catalog changed after this edition was prepared; prepare it again",
            ));
        }
        let accepted = prepared.accepted;
        self.records
            .insert(accepted.edition.id().to_owned(), Arc::new(accepted));
        self.revision += 1;
        Ok(())
    }

    /// Pin dataset, edition, signed record, and one complete allowed-use tuple.
    /// Friendly labels never choose between records or infer the latest revision.
    pub fn select(
        &self,
        dataset: &str,
        edition: &str,
        record_id: &str,
        use_context: &UseContext,
    ) -> Result<DatasetSelection> {
        label(dataset)?;
        label(edition)?;
        validate_revision_id(record_id)?;
        let record = self
            .records
            .get(record_id)
            .ok_or_else(|| invalid("select an admitted edition record by its exact identity"))?;
        if record.edition.dataset() != dataset || record.edition.edition() != edition {
            return Err(invalid(
                "selected record must match the explicit dataset and edition",
            ));
        }
        if !record.edition.eligible_uses().contains(use_context) {
            return Err(Error::UseDenied {
                operation: use_context.operation().to_owned(),
            });
        }
        Ok(DatasetSelection {
            accepted: Arc::clone(record),
            use_context: use_context.clone(),
        })
    }

    /// Verify a carried declaration against an accepted record and current accepted revisions.
    /// This does not by itself establish ancestry or permission for the receiving use.
    pub fn verify_binding(&self, binding: &DatasetBinding, dag: &PolicyDag) -> Result<()> {
        binding.validate()?;
        let record = self
            .records
            .get(binding.edition_record_id())
            .ok_or_else(|| invalid("dataset binding requires an admitted edition record"))?;
        if binding.dataset() != record.edition.dataset()
            || binding.edition() != record.edition.edition()
            || binding.source_object_id() != record.edition.source_object_id()
            || !same_bindings(binding.contracts(), record.edition.contracts())
        {
            return Err(invalid(
                "dataset binding must match its exact accepted edition record",
            ));
        }
        let current = selected_policies(binding.contracts(), dag)?;
        exact_contracts(&current, &record.policies)
    }

    /// Check every carried dataset against the receiving use and every current contract.
    /// Additional contracts require accepted revisions and complete contractual equality.
    /// Callers separately verify ancestry and authenticate the requested application identity.
    pub fn accepts(&self, context: &AdmissionContext<'_>, dag: &PolicyDag) -> Result<bool> {
        let use_context = context
            .use_context()
            .ok_or_else(|| invalid("dataset acceptance requires a complete use context"))?;
        let bindings = context.governance().dataset_bindings()?;
        if bindings.is_empty() {
            return Err(invalid(
                "dataset acceptance requires at least one carried dataset binding",
            ));
        }
        let policies = context.policies()?;
        for binding in &bindings {
            self.verify_binding(binding, dag)?;
            let record = &self.records[binding.edition_record_id()];
            if !record.edition.eligible_uses().contains(use_context) {
                return Ok(false);
            }
            for expected in &record.policies {
                if !policies
                    .iter()
                    .any(|policy| base_contract(policy) == base_contract(expected))
                {
                    return Err(invalid(
                        "every dataset contract must remain present in full",
                    ));
                }
            }
        }
        let mut revisions = BTreeSet::new();
        for policy in &policies {
            let id = policy
                .revision_id()
                .ok_or_else(|| invalid("every current contract needs an accepted revision"))?;
            if !revisions.insert(id) {
                return Err(invalid("each current policy revision must occur once"));
            }
            let revision = dag
                .get(id)
                .ok_or_else(|| invalid("current contract revision has not been admitted"))?;
            let expected = dag.select(id, revision.scope(), |_| Ok(true))?;
            if base_contract(policy) != base_contract(&expected) {
                return Err(invalid(
                    "current contract must match its complete accepted revision",
                ));
            }
        }
        Ok(true)
    }
}

fn selected_policies(contracts: &[ContractBinding], dag: &PolicyDag) -> Result<Vec<Governance>> {
    contracts
        .iter()
        .map(|binding| dag.select(binding.revision_id(), binding.scope(), |_| Ok(true)))
        .collect()
}
