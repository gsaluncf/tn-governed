//! Portable dataset and contract declarations, and the rule that adds one to a working copy.
use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize};

use super::{bounded_nonempty, invalid, label, MAX_BINDINGS, MAX_CONTRACTS};
use crate::governed::revision::validate_revision_id;
use crate::governed::Governance;
use crate::Result;

/// Exact signed policy revision and the scope under which it applies.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ContractBinding {
    revision_id: String,
    scope: String,
}

impl ContractBinding {
    /// Validate a lowercase TN row hash and explicit policy scope.
    pub fn new(revision_id: &str, scope: &str) -> Result<Self> {
        validate_revision_id(revision_id)?;
        label(scope)?;
        Ok(Self {
            revision_id: revision_id.to_owned(),
            scope: scope.to_owned(),
        })
    }
    /// Exact signed revision identity.
    pub fn revision_id(&self) -> &str {
        &self.revision_id
    }
    /// Explicit scope; no scope inference or wildcard matching occurs.
    pub fn scope(&self) -> &str {
        &self.scope
    }
}

impl<'de> Deserialize<'de> for ContractBinding {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            revision_id: String,
            scope: String,
        }
        let fields = Fields::deserialize(deserializer)?;
        Self::new(&fields.revision_id, &fields.scope).map_err(serde::de::Error::custom)
    }
}

pub(super) fn validate_contracts(contracts: &[ContractBinding]) -> Result<()> {
    bounded_nonempty(contracts, MAX_CONTRACTS, "contracts")?;
    let mut identities = BTreeSet::new();
    for contract in contracts {
        validate_revision_id(contract.revision_id())?;
        label(contract.scope())?;
        if !identities.insert(contract.revision_id()) {
            return Err(invalid(
                "each policy revision must occur once in the contract set",
            ));
        }
    }
    Ok(())
}

/// Portable declaration of an edition's origin, not an accepted capability.
/// A receiving catalog validates this declaration against an admitted signed record.
#[derive(Debug, Clone, Serialize)]
pub struct DatasetBinding {
    pub(super) dataset: String,
    pub(super) edition: String,
    pub(super) source_object_id: String,
    pub(super) edition_record_id: String,
    pub(super) contracts: Vec<ContractBinding>,
}

impl PartialEq for DatasetBinding {
    fn eq(&self, other: &Self) -> bool {
        self.dataset == other.dataset
            && self.edition == other.edition
            && self.source_object_id == other.source_object_id
            && self.edition_record_id == other.edition_record_id
            && same_bindings(&self.contracts, &other.contracts)
    }
}

impl Eq for DatasetBinding {}

impl DatasetBinding {
    /// Stable dataset identifier.
    pub fn dataset(&self) -> &str {
        &self.dataset
    }
    /// Explicit edition identifier.
    pub fn edition(&self) -> &str {
        &self.edition
    }
    /// Exact released source publication.
    pub fn source_object_id(&self) -> &str {
        &self.source_object_id
    }
    /// Exact signed, separately admitted edition record.
    pub fn edition_record_id(&self) -> &str {
        &self.edition_record_id
    }
    /// Required policy revisions and scopes.
    pub fn contracts(&self) -> &[ContractBinding] {
        &self.contracts
    }
    pub(in crate::governed) fn validate(&self) -> Result<()> {
        label(&self.dataset)?;
        label(&self.edition)?;
        validate_revision_id(&self.source_object_id)?;
        validate_revision_id(&self.edition_record_id)?;
        if self.source_object_id == self.edition_record_id {
            return Err(invalid(
                "edition record must identify a separate earlier source publication",
            ));
        }
        validate_contracts(&self.contracts)
    }
}

impl<'de> Deserialize<'de> for DatasetBinding {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            dataset: String,
            edition: String,
            source_object_id: String,
            edition_record_id: String,
            contracts: Vec<ContractBinding>,
        }
        let fields = Fields::deserialize(deserializer)?;
        let binding = Self {
            dataset: fields.dataset,
            edition: fields.edition,
            source_object_id: fields.source_object_id,
            edition_record_id: fields.edition_record_id,
            contracts: fields.contracts,
        };
        binding.validate().map_err(serde::de::Error::custom)?;
        Ok(binding)
    }
}

pub(super) fn same_bindings(left: &[ContractBinding], right: &[ContractBinding]) -> bool {
    left.len() == right.len()
        && left.iter().collect::<BTreeSet<_>>() == right.iter().collect::<BTreeSet<_>>()
}

impl Governance {
    /// Validated selected origins. These are carried facts; the catalog admits their use.
    pub fn dataset_bindings(&self) -> Result<Vec<DatasetBinding>> {
        let Some(value) = self.get("dataset_bindings") else {
            return Ok(Vec::new());
        };
        let values = value
            .as_array()
            .ok_or_else(|| invalid("dataset bindings require an array"))?;
        if values.len() > MAX_BINDINGS {
            return Err(invalid("object supports at most 1024 dataset bindings"));
        }
        let bindings = Vec::<DatasetBinding>::deserialize(value)
            .map_err(|error| invalid(format!("dataset bindings: {error}")))?;
        let mut editions = BTreeSet::new();
        for binding in &bindings {
            if !editions.insert(binding.edition_record_id()) {
                return Err(invalid(
                    "each edition record must have exactly one dataset binding",
                ));
            }
        }
        Ok(bindings)
    }
}

/// Whether `addition` joins `bindings` as a new declaration. An identical one
/// already there adds nothing; a different declaration for the same edition
/// record, or a full list, is refused.
pub(super) fn check_binding_addition(bindings: &[DatasetBinding], addition: &DatasetBinding) -> Result<bool> {
    match bindings
        .iter()
        .find(|binding| binding.edition_record_id() == addition.edition_record_id())
    {
        Some(existing) if existing != addition => Err(invalid(
            "a selected edition record cannot acquire a different binding",
        )),
        Some(_) => Ok(false),
        None if bindings.len() >= MAX_BINDINGS => {
            Err(invalid("object supports at most 1024 dataset bindings"))
        }
        None => Ok(true),
    }
}

/// Add each binding to `governance`'s dataset bindings, in order, by the same rule.
pub(in crate::governed) fn merge_bindings(
    governance: &mut Governance,
    additions: impl IntoIterator<Item = DatasetBinding>,
) -> Result<()> {
    let mut bindings = governance.dataset_bindings()?;
    for binding in additions {
        binding.validate()?;
        if check_binding_addition(&bindings, &binding)? {
            bindings.push(binding);
        }
    }
    if !bindings.is_empty() {
        governance
            .fields
            .insert("dataset_bindings".into(), serde_json::to_value(bindings)?);
    }
    Ok(())
}
