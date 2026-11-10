//! Signed dataset edition records: drafted after their source is signed, decoded after admission.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::bindings::validate_contracts;
use super::{bounded_nonempty, invalid, label, ContractBinding, DatasetBinding, EvaluatorArtifactSet,
    DATASET_EDITION_GROUP, DATASET_EDITION_TYPE, EDITION_SCHEMA, MAX_GRANT_BYTES, MAX_ITEMS, MAX_USES};
use crate::governed::revision::validate_revision_id;
use crate::governed::{validate_group, Governance, GovernedDraft, GovernedObject, OpenedObject, UseContext, GOVERNANCE_GROUP};
use crate::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EditionBody {
    schema: String,
    dataset: String,
    edition: String,
    source_object_id: String,
    source_writer: String,
    source_type: String,
    source_groups: Vec<String>,
    contracts: Vec<ContractBinding>,
    eligible_uses: Vec<UseContext>,
    grant_ref: String,
    evaluator_artifacts: Vec<EvaluatorArtifactSet>,
}

impl EditionBody {
    pub(super) fn validate(&self) -> Result<()> {
        if self.schema != EDITION_SCHEMA {
            return Err(invalid("required tn-dataset-edition@v1 schema"));
        }
        label(&self.dataset)?;
        label(&self.edition)?;
        label(&self.source_type)?;
        validate_revision_id(&self.source_object_id)?;
        crate::trust::parse_ed25519_did_key(&self.source_writer)
            .map_err(|_| invalid("source writer requires an Ed25519 did:key"))?;
        validate_groups(&self.source_groups)?;
        validate_contracts(&self.contracts)?;
        validate_eligible_uses(&self.eligible_uses)?;
        validate_grant_ref(&self.grant_ref)?;
        validate_artifact_coverage(&self.evaluator_artifacts, &self.contracts)
    }
}

/// Complete, bounded use tuples, each once.
fn validate_eligible_uses(eligible_uses: &[UseContext]) -> Result<()> {
    bounded_nonempty(eligible_uses, MAX_USES, "eligible uses")?;
    let mut uses = BTreeSet::new();
    for use_context in eligible_uses {
        // Revalidation also protects this record if UseContext's decoding changes.
        UseContext::new(
            use_context.application(),
            use_context.purpose(),
            use_context.operation(),
        )?;
        if !uses.insert((
            use_context.application(),
            use_context.purpose(),
            use_context.operation(),
        )) {
            return Err(invalid("each complete eligible-use tuple must occur once"));
        }
    }
    Ok(())
}

/// One to 2048 bytes without control characters.
fn validate_grant_ref(grant_ref: &str) -> Result<()> {
    if grant_ref.trim().is_empty()
        || grant_ref.len() > MAX_GRANT_BYTES
        || grant_ref.chars().any(char::is_control)
    {
        return Err(invalid(
            "grant reference requires 1 to 2048 bytes without control characters",
        ));
    }
    Ok(())
}

/// No artifact sets, for native callbacks, or exactly one per required contract.
fn validate_artifact_coverage(
    evaluator_artifacts: &[EvaluatorArtifactSet],
    contracts: &[ContractBinding],
) -> Result<()> {
    if evaluator_artifacts.len() > MAX_ITEMS {
        return Err(invalid("evaluator artifacts exceeds 256 entries"));
    }
    let revisions: BTreeSet<_> = contracts.iter().map(ContractBinding::revision_id).collect();
    let mut artifacts = BTreeSet::new();
    for artifact in evaluator_artifacts {
        if !revisions.contains(artifact.policy_revision())
            || !artifacts.insert(artifact.policy_revision())
        {
            return Err(invalid(
                "each artifact set must identify a distinct required contract",
            ));
        }
    }
    if !artifacts.is_empty() && artifacts != revisions {
        return Err(invalid(
            "every required contract needs exactly one evaluator artifact set",
        ));
    }
    Ok(())
}

pub(super) fn validate_groups(groups: &[String]) -> Result<()> {
    bounded_nonempty(groups, MAX_ITEMS, "source groups")?;
    let mut names = BTreeSet::new();
    for group in groups {
        label(group)?;
        validate_group(group)?;
        if group == GOVERNANCE_GROUP || !names.insert(group) {
            return Err(invalid("source groups must be distinct business groups"));
        }
    }
    Ok(())
}

/// An edition record prepared after its source publication has been signed.
#[derive(Debug, Clone)]
pub struct DatasetEditionDraft {
    body: EditionBody,
}

impl DatasetEditionDraft {
    /// Bind an already verified publication to explicit contracts and eligible-use tuples.
    /// Policy authority and actual source contracts are checked by the catalog and receipt.
    #[allow(clippy::too_many_arguments)]
    pub fn new<I, S>(
        dataset: &str,
        edition: &str,
        source: &GovernedObject,
        source_groups: I,
        contracts: Vec<ContractBinding>,
        eligible_uses: Vec<UseContext>,
        grant_ref: &str,
        evaluator_artifacts: Vec<EvaluatorArtifactSet>,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let body = EditionBody {
            schema: EDITION_SCHEMA.to_owned(),
            dataset: dataset.to_owned(),
            edition: edition.to_owned(),
            source_object_id: source.id().to_owned(),
            source_writer: source.writer().to_owned(),
            source_type: source.object_type().to_owned(),
            source_groups: source_groups
                .into_iter()
                .map(|s| s.as_ref().to_owned())
                .collect(),
            contracts,
            eligible_uses,
            grant_ref: grant_ref.to_owned(),
            evaluator_artifacts,
        };
        body.validate()?;
        if body
            .source_groups
            .iter()
            .any(|group| !source.group_names().contains(&group.as_str()))
        {
            return Err(invalid(
                "edition source groups must occur in the verified source publication",
            ));
        }
        Ok(Self { body })
    }

    /// Build the existing governed draft under the record's administration contract.
    pub fn into_draft(self, administration_contract: Governance) -> Result<GovernedDraft> {
        self.body.validate()?;
        GovernedDraft::new(DATASET_EDITION_TYPE, administration_contract)?
            .group(DATASET_EDITION_GROUP, self.body)
    }
}

/// Structurally validated edition record opened through ordinary TN governance admission.
#[derive(Debug, Clone)]
pub struct DatasetEdition {
    object: GovernedObject,
    pub(super) body: EditionBody,
}

impl DatasetEdition {
    /// Decode an edition only after ordinary governance acceptance and group opening.
    pub fn from_opened(opened: &OpenedObject) -> Result<Self> {
        if opened.object().object_type() != DATASET_EDITION_TYPE {
            return Err(invalid("required tn.dataset.edition object type"));
        }
        let payload = opened
            .groups()
            .get(DATASET_EDITION_GROUP)
            .ok_or_else(|| invalid("open the dataset_edition group before decoding its record"))?;
        let body: EditionBody = serde_json::from_value(payload.clone())
            .map_err(|e| invalid(format!("invalid edition record: {e}")))?;
        body.validate()?;
        if body.source_object_id == opened.object().id() {
            return Err(invalid(
                "edition record must identify a separate earlier source publication",
            ));
        }
        Ok(Self {
            object: opened.object().clone(),
            body,
        })
    }
    /// Signed edition-record identity.
    pub fn id(&self) -> &str {
        self.object.id()
    }
    /// Authenticated catalog writer; admission applies the application's authority rule.
    pub fn writer(&self) -> &str {
        self.object.writer()
    }
    /// Stable dataset identifier.
    pub fn dataset(&self) -> &str {
        &self.body.dataset
    }
    /// Explicit edition; no ordering is inferred.
    pub fn edition(&self) -> &str {
        &self.body.edition
    }
    /// Exact released source identity.
    pub fn source_object_id(&self) -> &str {
        &self.body.source_object_id
    }
    /// Expected source signer.
    pub fn source_writer(&self) -> &str {
        &self.body.source_writer
    }
    /// Expected source object type.
    pub fn source_type(&self) -> &str {
        &self.body.source_type
    }
    /// Business groups that this edition may supply.
    pub fn source_groups(&self) -> &[String] {
        &self.body.source_groups
    }
    /// Complete required policy revision bindings.
    pub fn contracts(&self) -> &[ContractBinding] {
        &self.body.contracts
    }
    /// Allowed tuples; separate tuple values may not be recombined.
    pub fn eligible_uses(&self) -> &[UseContext] {
        &self.body.eligible_uses
    }
    /// Catalog authority's entitlement reference.
    pub fn grant_ref(&self) -> &str {
        &self.body.grant_ref
    }
    /// Per-revision artifact digests to verify before external evaluator loading.
    /// An explicitly empty list supports consumers that use native callbacks.
    /// A nonempty list covers every required contract revision exactly once.
    pub fn evaluator_artifacts(&self) -> &[EvaluatorArtifactSet] {
        &self.body.evaluator_artifacts
    }
    /// Exact signed envelope for retention and forwarding.
    pub fn object(&self) -> &GovernedObject {
        &self.object
    }

    pub(super) fn binding(&self) -> DatasetBinding {
        DatasetBinding {
            dataset: self.dataset().to_owned(),
            edition: self.edition().to_owned(),
            source_object_id: self.source_object_id().to_owned(),
            edition_record_id: self.id().to_owned(),
            contracts: self.contracts().to_vec(),
        }
    }
}
