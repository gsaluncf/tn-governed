//! Governance views and admissions: what an application accepted before anything opens.
use std::collections::BTreeSet;
use std::sync::Arc;

use crate::governed::{invalid, AdmissionContext, Governance, GovernedObject, UseContext, GOVERNANCE_GROUP};
use crate::{Error, Result};

/// The opened contract and its verified source, before business-data admission.
#[derive(Clone)]
pub struct GovernanceView {
    pub(super) object: GovernedObject,
    pub(super) governance: Governance,
    pub(super) reader_identity: Arc<()>,
    pub(super) governance_digest: Option<String>,
}

impl GovernanceView {
    /// Digest of the exact governance bytes this view decrypted, for bound objects.
    pub(super) fn digest(&self) -> Result<&str> {
        self.governance_digest
            .as_deref()
            .ok_or_else(|| invalid("an unbound object has no governance digest"))
    }

    /// Accept a complete use and immutable group set under this reader context.
    /// All structural checks precede the application decision; no business group
    /// is opened until the resulting admission is passed to the same reader.
    pub fn accept<I, S, F>(
        self,
        use_context: UseContext,
        groups: I,
        decide: F,
    ) -> Result<AdmittedObject>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        F: FnOnce(&AdmissionContext<'_>) -> Result<bool>,
    {
        let groups = selected_groups(&self.object, groups)?;
        self.accept_groups(use_context, groups, decide)
    }

    /// Accept `groups`, already checked to be held by this object or by an object
    /// it carries. The application decides; nothing opens here.
    pub(super) fn accept_groups<F>(
        self,
        use_context: UseContext,
        groups: Vec<String>,
        decide: F,
    ) -> Result<AdmittedObject>
    where
        F: FnOnce(&AdmissionContext<'_>) -> Result<bool>,
    {
        if groups.is_empty() {
            return Err(invalid(
                "strict admission requires at least one business group",
            ));
        }
        ask(&self, &use_context, &groups, decide)?;
        Ok(AdmittedObject {
            view: self,
            operation: use_context.operation().to_owned(),
            strict: Some(AcceptedUse {
                use_context,
                groups,
            }),
        })
    }

    /// Legacy operation-only admission with verified source context. Use
    /// [`Self::accept`] for complete use and immutable selected-group admission.
    pub fn authorize_with<F>(self, operation: &str, decide: F) -> Result<AdmittedObject>
    where
        F: FnOnce(&AdmissionContext<'_>) -> Result<bool>,
    {
        if operation.trim().is_empty() {
            return Err(invalid("operation must be nonempty"));
        }
        let context = AdmissionContext {
            object: &self.object,
            governance: &self.governance,
            operation,
            use_context: None,
            groups: None,
        };
        if !decide(&context)? {
            return Err(Error::UseDenied {
                operation: operation.to_owned(),
            });
        }
        Ok(AdmittedObject {
            view: self,
            operation: operation.to_owned(),
            strict: None,
        })
    }
    /// The authenticated contract the application is to evaluate.
    pub fn governance(&self) -> &Governance {
        &self.governance
    }
    /// Complete verified source, ready for unchanged forwarding.
    pub fn object(&self) -> &GovernedObject {
        &self.object
    }

    /// Legacy contract-and-operation decision. Use [`Self::accept`] to bind
    /// complete use and selected groups under this reader context.
    /// The callback returns `true` for approval; its errors propagate. Reader
    /// keys remain the separate requirement for opening the admitted groups.
    pub fn authorize<F>(self, operation: &str, decide: F) -> Result<AdmittedObject>
    where
        F: FnOnce(&Governance, &str) -> Result<bool>,
    {
        if operation.trim().is_empty() {
            return Err(invalid("operation must be nonempty"));
        }
        if !decide(&self.governance, operation)? {
            return Err(Error::UseDenied {
                operation: operation.to_owned(),
            });
        }
        Ok(AdmittedObject {
            view: self,
            operation: operation.to_owned(),
            strict: None,
        })
    }
}

/// An object admitted for a complete use, or a legacy operation-only decision.
#[derive(Clone)]
pub struct AdmittedObject {
    pub(super) view: GovernanceView,
    pub(super) operation: String,
    pub(super) strict: Option<AcceptedUse>,
}

#[derive(Clone)]
pub(super) struct AcceptedUse {
    pub(super) use_context: UseContext,
    pub(super) groups: Vec<String>,
}

impl AdmittedObject {
    /// Whether `other` is this exact admission: one object, one reader context,
    /// one accepted use and group set.
    pub(in crate::governed) fn same_admission(&self, other: &AdmittedObject) -> bool {
        self.object().id() == other.object().id()
            && Arc::ptr_eq(&self.view.reader_identity, &other.view.reader_identity)
            && self.use_context() == other.use_context()
            && self.selected_groups() == other.selected_groups()
    }
    /// Complete accepted use, absent only for the legacy operation-only path.
    pub fn use_context(&self) -> Option<&UseContext> {
        self.strict.as_ref().map(|accepted| &accepted.use_context)
    }
    /// Maximum business group set accepted on the strict path.
    pub fn selected_groups(&self) -> Option<&[String]> {
        self.strict
            .as_ref()
            .map(|accepted| accepted.groups.as_slice())
    }
    /// Operation accepted by the application callback.
    pub fn operation(&self) -> &str {
        &self.operation
    }
    /// Accepted contract.
    pub fn governance(&self) -> &Governance {
        &self.view.governance
    }
    /// Verified object to which the decision applies.
    pub fn object(&self) -> &GovernedObject {
        &self.view.object
    }
    /// Ask `decide` again about this exact strict admission; a refusal changes nothing.
    pub(in crate::governed) fn confirm<F>(&self, decide: &mut F) -> Result<()>
    where
        F: FnMut(&AdmissionContext<'_>) -> Result<bool>,
    {
        let accepted = self
            .strict
            .as_ref()
            .ok_or_else(|| invalid("only a strict admission is confirmed before receipt"))?;
        ask(&self.view, &accepted.use_context, &accepted.groups, decide)
    }
    /// The governance view this admission was made on, for its governance hash key.
    pub fn view(&self) -> &GovernanceView {
        &self.view
    }
}

/// Put one complete use and group set to the application; a refusal is `UseDenied`.
fn ask<F>(view: &GovernanceView, use_context: &UseContext, groups: &[String], decide: F) -> Result<()>
where
    F: FnOnce(&AdmissionContext<'_>) -> Result<bool>,
{
    let context = AdmissionContext {
        object: &view.object,
        governance: &view.governance,
        operation: use_context.operation(),
        use_context: Some(use_context),
        groups: Some(groups),
    };
    if !decide(&context)? {
        return Err(Error::UseDenied {
            operation: use_context.operation().to_owned(),
        });
    }
    Ok(())
}

pub(super) fn selected_groups<I, S>(object: &GovernedObject, groups: I) -> Result<Vec<String>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut selected = BTreeSet::new();
    for name in groups {
        let name = name.as_ref();
        if name == GOVERNANCE_GROUP
            || !object.groups.contains_key(name)
            || !selected.insert(name.to_owned())
        {
            return Err(invalid(format!(
                "select each present business group once: {name:?}"
            )));
        }
    }
    Ok(selected.into_iter().collect())
}
