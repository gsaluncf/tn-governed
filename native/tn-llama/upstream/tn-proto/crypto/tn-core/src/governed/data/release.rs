//! Drafting, signing, and retaining a working copy's successors.
use super::DataObject;
use crate::governed::carried::carried_holders;
use crate::governed::{
    invalid, validate_name, AttachmentContext, Governance, GovernedDraft, GovernedObject,
    GovernedWriter, ReleaseContext, SourceReference, UseContext,
};
use crate::{Error, Result};
use serde::Serialize;
use serde_json::{json, Value};

impl DataObject {
    /// The draft of the next release under `release_context`: the opened groups, the
    /// manifest, the causal inputs, and the whole holders of every unopened group.
    pub(crate) fn draft(&self, object_type: &str, release_context: Value) -> Result<GovernedDraft> {
        let mut policy = self.governance.clone();
        if !self.sources.is_empty() {
            policy.fields.insert("source_lineage".to_owned(), serde_json::to_value(&self.sources)?);
        }
        policy.fields.insert("release_context".to_owned(), release_context);
        let mut draft = GovernedDraft::new(object_type, policy)?;
        for (name, fields) in &self.groups {
            draft = draft.group(name, fields)?;
        }
        if let Some(name) = &self.manifest {
            if !self.groups.contains_key(name) {
                return Err(invalid(format!("manifest {name:?} must be an opened business group")));
            }
            draft = draft.manifest(name)?;
        }
        draft.carried = carried_holders(&self.opaque, &self.holders);
        Ok(draft)
    }
    pub(crate) fn record_snapshot(
        &mut self,
        snapshot: GovernedObject,
        operation: &str,
    ) -> Result<()> {
        let reference = SourceReference::new(
            &snapshot,
            &self.governance,
            self.groups.keys().cloned().collect(),
            operation,
        )?;
        self.object_type = snapshot.object_type().to_owned();
        self.history.push(snapshot);
        self.sources = vec![reference];
        self.changed();
        self.unreleased_changes = false;
        Ok(())
    }
}

/// One release: what the decision sees and what the successor records.
struct Release<'a> {
    object_type: &'a str,
    purpose: &'a str,
    destination: &'a str,
    use_context: Option<&'a UseContext>,
}

impl Release<'_> {
    /// The signed release context: the complete use when one was given.
    fn context(&self) -> Value {
        match self.use_context {
            Some(use_context) => json!({
                "application": use_context.application(), "purpose": use_context.purpose(),
                "operation": use_context.operation(), "destination": self.destination,
            }),
            None => json!({"purpose": self.purpose, "destination": self.destination}),
        }
    }
}

impl GovernedWriter<'_> {
    /// Originate data with its required contract and retain the initial signed version.
    pub fn create_obj(
        &self,
        object_type: &str,
        policy: Governance,
        group: &str,
        fields: impl Serialize,
    ) -> Result<DataObject> {
        self.create_obj_with_groups(object_type, policy, [(group, fields)])
    }

    /// Originate a complete group collection in one signed initial version.
    /// Group routing remains explicit; `tn.agents` comes from the required policy.
    pub fn create_obj_with_groups<I, S, V>(
        &self,
        object_type: &str,
        policy: Governance,
        groups: I,
    ) -> Result<DataObject>
    where
        I: IntoIterator<Item = (S, V)>,
        S: AsRef<str>,
        V: Serialize,
    {
        let mut data = DataObject::new_with_groups(object_type, policy, groups)?;
        let context = json!({"purpose": "create", "destination": "origin"});
        let sealed = self.seal(data.draft(object_type, context)?)?;
        data.record_snapshot(sealed, "create")?;
        Ok(data)
    }

    /// Add policy after the application accepts this writer's attachment authority.
    pub fn attach<F>(&self, data: &mut DataObject, policy: Governance, decide: F) -> Result<()>
    where
        F: FnOnce(&AttachmentContext<'_>) -> Result<bool>,
    {
        data.attach(self.did(), policy, decide)
    }

    /// Admit the current data for its destination and purpose, then retain a signed version.
    pub fn release<F>(
        &self,
        data: &mut DataObject,
        object_type: &str,
        purpose: &str,
        destination: &str,
        decide: F,
    ) -> Result<GovernedObject>
    where
        F: FnOnce(&ReleaseContext<'_>) -> Result<bool>,
    {
        validate_name(object_type)?;
        if purpose.trim().is_empty() || destination.trim().is_empty() {
            return Err(invalid("release requires purpose and destination"));
        }
        let release = Release { object_type, purpose, destination, use_context: None };
        self.release_as(data, release, decide)
    }

    /// Release under an explicit application, purpose and operation.
    pub fn release_for<F>(
        &self,
        data: &mut DataObject,
        object_type: &str,
        use_context: &UseContext,
        destination: &str,
        decide: F,
    ) -> Result<GovernedObject>
    where
        F: FnOnce(&ReleaseContext<'_>) -> Result<bool>,
    {
        validate_name(object_type)?;
        if destination.trim().is_empty() {
            return Err(invalid("release requires a destination"));
        }
        let purpose = use_context.purpose();
        let release = Release { object_type, purpose, destination, use_context: Some(use_context) };
        self.release_as(data, release, decide)
    }

    /// Ask the application, then sign the successor and retain it as the new version.
    /// A refusal names the use's operation, or `release:<purpose>` without one.
    fn release_as<F>(&self, data: &mut DataObject, release: Release<'_>, decide: F) -> Result<GovernedObject>
    where
        F: FnOnce(&ReleaseContext<'_>) -> Result<bool>,
    {
        let context = ReleaseContext {
            writer: self.did(),
            data,
            object_type: release.object_type,
            purpose: release.purpose,
            destination: release.destination,
            use_context: release.use_context,
        };
        if !decide(&context)? {
            let operation = match release.use_context {
                Some(use_context) => use_context.operation().to_owned(),
                None => format!("release:{}", release.purpose),
            };
            return Err(Error::UseDenied { operation });
        }
        let sealed = self.seal(data.draft(release.object_type, release.context())?)?;
        let operation = release.use_context.map_or(release.purpose, UseContext::operation);
        data.record_snapshot(sealed.clone(), operation)?;
        Ok(sealed)
    }
}
