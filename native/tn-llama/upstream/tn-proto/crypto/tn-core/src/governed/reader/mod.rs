use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;

use hmac::Hmac;
use serde_json::{Map, Value};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::canonical::canonical_bytes;
use crate::cipher::GroupCipher;
use crate::sealed_object::GroupBlock;
use crate::{Error, Result};

use super::binding::{self, Input};
use super::route::{AdmittedRoute, Route, Stop};
use super::object::parse_json;
use super::policy::string_field;
use super::{
    invalid, validate_group, DatasetSelection, Governance, GovernedObject,
    UseContext, GOVERNANCE_GROUP,
};

mod admission;
mod opened;
mod prepared;
#[cfg(test)]
mod tests;

pub use admission::{AdmittedObject, GovernanceView};
pub use opened::OpenedObject;
use admission::selected_groups;
use prepared::Keys;

/// An object a reader receives: exact wire text, parsed and verified on receipt,
/// or an object already verified, which is used as is.
pub enum Incoming<'a> {
    /// Exact transport text, parsed and verified on receipt.
    Wire(&'a str),
    /// An object `GovernedObject::parse` already verified.
    Object(&'a GovernedObject),
}

impl<'a> From<&'a str> for Incoming<'a> {
    fn from(wire: &'a str) -> Self {
        Self::Wire(wire)
    }
}

impl<'a> From<&'a String> for Incoming<'a> {
    fn from(wire: &'a String) -> Self {
        Self::Wire(wire)
    }
}

impl<'a> From<&'a GovernedObject> for Incoming<'a> {
    fn from(object: &'a GovernedObject) -> Self {
        Self::Object(object)
    }
}

impl<'a> Incoming<'a> {
    fn object(self) -> Result<Cow<'a, GovernedObject>> {
        match self {
            Self::Wire(wire) => GovernedObject::parse(wire).map(Cow::Owned),
            Self::Object(object) => Ok(Cow::Borrowed(object)),
        }
    }
}

/// Reader material indexed by group. Multiple candidates support retained
/// historical keys and objects from different publishers.
#[derive(Default)]
pub struct GovernedReader {
    groups: BTreeMap<String, Vec<Arc<dyn GroupCipher>>>,
    indexes: BTreeMap<String, Hmac<Sha256>>,
    allow_unbound: bool,
    identity: Arc<()>,
}

impl GovernedReader {
    /// Legacy operation-only receipt. Use [`Self::receive_for`] to bind the
    /// complete use, reader context and selected groups before opening data.
    pub fn receive<'a, I, S, F>(
        &self,
        source: impl Into<Incoming<'a>>,
        operation: &str,
        groups: I,
        decide: F,
    ) -> Result<super::DataObject>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        F: FnOnce(&super::AdmissionContext<'_>) -> Result<bool>,
    {
        let object = source.into().object()?;
        let admitted = self
            .governance(&object)?
            .authorize_with(operation, decide)?;
        super::DataObject::from_opened(self.open(&admitted, groups)?)
    }

    /// Verify the exact source and any edition selections, admit its complete use
    /// and selected groups, then open business data under this reader.
    ///
    /// A selected group the source carries in a whole input object opens from its
    /// nearest holder. Every object on the path to that holder must accept the
    /// use of the group, the source first, and each selection is verified against
    /// the object it pins before any decision. The source stays the working
    /// copy's input; each holder's policies and bindings join its governance.
    pub fn receive_for<'a, 's, I, S, F>(
        &self,
        source: impl Into<Incoming<'a>>,
        use_context: &UseContext,
        groups: I,
        selections: impl IntoIterator<Item = &'s DatasetSelection>,
        decide: F,
    ) -> Result<super::DataObject>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        F: FnMut(&super::AdmissionContext<'_>) -> Result<bool>,
    {
        let route = self.admit_route(source, use_context, groups, selections, decide)?;
        self.open_route(&route)
    }

    /// Receive a route this reader admitted earlier. Each object on it is asked
    /// again with `decide`, the source first; then its groups open and assemble as
    /// in [`Self::receive_for`], without parsing the source or decrypting any
    /// governance again.
    pub fn receive_admitted<F>(&self, route: &AdmittedRoute, mut decide: F) -> Result<super::DataObject>
    where
        F: FnMut(&super::AdmissionContext<'_>) -> Result<bool>,
    {
        for (admitted, _) in route.stops() {
            admitted.confirm(&mut decide)?;
        }
        self.open_route(route)
    }

    /// Open the groups each object on an admitted route supplies, and assemble them.
    /// The route already validated every group name, so they are not checked again.
    fn open_route(&self, route: &AdmittedRoute) -> Result<super::DataObject> {
        let opened = route
            .stops()
            .map(|(admitted, supplied)| self.open_selected(admitted, supplied.to_vec(), None))
            .collect::<Result<Vec<_>>>()?;
        self.assemble(route, opened)
    }

    /// Decide a strict receipt without opening anything: the same route, selection
    /// checks, and acceptances as [`Self::receive_for`]. No group key is needed.
    /// Returns the policies the received working copy would hold.
    pub fn admit_for<'a, 's, I, S, F>(
        &self,
        source: impl Into<Incoming<'a>>,
        use_context: &UseContext,
        groups: I,
        selections: impl IntoIterator<Item = &'s DatasetSelection>,
        decide: F,
    ) -> Result<Vec<Governance>>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        F: FnMut(&super::AdmissionContext<'_>) -> Result<bool>,
    {
        self.admit_route(source, use_context, groups, selections, decide)?.policies()
    }

    /// Resolve the route, verify every selection, then ask each object on it, the
    /// source first. Every structural check precedes the first decision. Open a
    /// supplier's groups with its admission and pass them to [`Self::assemble`].
    pub fn admit_route<'a, 's, I, S, F>(
        &self,
        source: impl Into<Incoming<'a>>,
        use_context: &UseContext,
        groups: I,
        selections: impl IntoIterator<Item = &'s DatasetSelection>,
        mut decide: F,
    ) -> Result<AdmittedRoute>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        F: FnMut(&super::AdmissionContext<'_>) -> Result<bool>,
    {
        let object = source.into().object()?;
        let route = Route::resolve(&object, groups)?;
        let selected = route.selections(selections)?;
        let views = route
            .stops
            .iter()
            .map(|stop| self.verified_view(stop, use_context, selected.get(stop.object.id())))
            .collect::<Result<Vec<_>>>()?;
        let admitted = views
            .into_iter()
            .zip(&route.stops)
            .map(|(view, stop)| view.accept_groups(use_context.clone(), stop.accepted.clone(), &mut decide))
            .collect::<Result<Vec<_>>>()?;
        let selections = selected.into_values().cloned().collect();
        Ok(AdmittedRoute::new(route, admitted, selections))
    }

    /// The working copy of groups opened on `route`. Each opened part must come
    /// from this route's own admission and hold only groups its object supplies;
    /// objects with no opened part still contribute their policies. The received
    /// object stays the only causal input, and the route's selections bind.
    pub fn assemble(&self, route: &AdmittedRoute, opened: Vec<OpenedObject>) -> Result<super::DataObject> {
        let mut parts: Vec<Option<OpenedObject>> = route.stops().map(|_| None).collect();
        for part in opened {
            let index = route.position(&part)?;
            if parts[index].replace(part).is_some() {
                return Err(invalid("each object on a route opens once"));
            }
        }
        let mut parts = parts
            .into_iter()
            .zip(route.stops())
            .map(|(part, (admitted, _))| match part {
                Some(part) => Ok(part),
                None => self.open_selected(admitted, Vec::new(), None),
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter();
        let direct = parts.next().expect("a route starts at its source");
        let mut data = super::DataObject::from_route(direct, parts.collect())?;
        for selection in route.selections() {
            data.bind_selection(selection)?;
        }
        Ok(data)
    }

    /// The governance of one object on a receipt route, with its selection verified.
    fn verified_view(
        &self,
        stop: &Stop,
        use_context: &UseContext,
        selection: Option<&&DatasetSelection>,
    ) -> Result<GovernanceView> {
        let view = self.governance(&stop.object)?;
        if let Some(selection) = selection {
            selection.verify_source(&view, use_context, &stop.supplied)?;
        }
        Ok(view)
    }

    /// Start a reader with no group material.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a cipher capable of opening the named group.
    pub fn with_group(mut self, name: &str, cipher: Arc<dyn GroupCipher>) -> Result<Self> {
        validate_group(name)?;
        self.groups.entry(name.to_owned()).or_default().push(cipher);
        // A changed capability snapshot must obtain a new strict acceptance.
        self.identity = Arc::new(());
        Ok(self)
    }

    /// Add the governance group's index key. Bound data groups need it to derive
    /// the governance hash key from the decrypted governance and manifest.
    pub fn with_governance_index_key(self, index_key: &[u8]) -> Result<Self> {
        self.with_group_index_key(GOVERNANCE_GROUP, index_key)
    }

    /// Add a group's index key. Opening that group then recomputes each field hash
    /// from the opened value and refuses a value that differs. Without it, opened
    /// fields are checked by name only: an unlock needs no index key.
    pub fn with_group_index_key(self, name: &str, index_key: &[u8]) -> Result<Self> {
        self.with_group_index(name, crate::indexing::build_hmac_template(index_key)?)
    }

    /// One index key per group, so a field hash or a governance hash key is never
    /// ambiguous about the key that made it.
    pub(crate) fn with_group_index(mut self, name: &str, index: Hmac<Sha256>) -> Result<Self> {
        validate_group(name)?;
        if self.indexes.insert(name.to_owned(), index).is_some() {
            return Err(invalid(format!("reader already holds an index key for {name:?}")));
        }
        self.identity = Arc::new(());
        Ok(self)
    }

    /// Also open objects written before binding. Their groups are bound only to
    /// the shared label, and [`GovernedObject::bound`] reports them as unbound.
    pub fn allow_unbound(mut self) -> Self {
        self.allow_unbound = true;
        self.identity = Arc::new(());
        self
    }

    /// Refuse a label-only object unless this reader explicitly allows them.
    fn require_bound(&self, object: &GovernedObject) -> Result<()> {
        if !object.bound() && !self.allow_unbound {
            return Err(invalid(
                "object is not bound to its governance; open it with a reader that allows unbound objects",
            ));
        }
        Ok(())
    }

    /// Open only the contract, retaining every business group as ciphertext.
    pub fn governance(&self, object: &GovernedObject) -> Result<GovernanceView> {
        self.require_bound(object)?;
        let aad = match &object.binding {
            Some(bound) => bound.aad(GOVERNANCE_GROUP, Input::Governance)?,
            None => canonical_bytes(&Value::Object((*object.marker).clone()))?,
        };
        let (body, bytes) = self.decrypt(object, GOVERNANCE_GROUP, &aad)?;
        let governance_digest = object.bound().then(|| binding::digest(&bytes));
        let governance = Governance::from_body(string_field(&object.marker, "governed_by")?, body)?;
        governance.policies()?;
        governance.source_references()?;
        governance.dataset_bindings()?;
        if governance.policy_ref() != string_field(&object.marker, "policy")? {
            return Err(invalid(
                "opened policy must match its authenticated AAD reference",
            ));
        }
        Ok(GovernanceView {
            object: object.clone(),
            governance,
            reader_identity: Arc::clone(&self.identity),
            governance_digest,
        })
    }

    /// Open precisely the named business groups after application admission.
    /// Every requested group must open; other ciphertext is retained unchanged.
    pub fn open<I, S>(&self, admitted: &AdmittedObject, groups: I) -> Result<OpenedObject>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.open_selected(admitted, selected_groups(&admitted.view.object, groups)?, None)
    }

    /// Open bound data groups under a governance hash key supplied by the caller,
    /// such as the key a model passed back to its decrypt tool. A key other than
    /// the one the writer bound fails decryption, and nothing changes.
    pub fn open_with_hash_key<I, S>(
        &self,
        admitted: &AdmittedObject,
        groups: I,
        hash_key: &str,
    ) -> Result<OpenedObject>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let selected = selected_groups(&admitted.view.object, groups)?;
        self.open_selected(admitted, selected, Some(hash_key))
    }

    /// The governance hash key of a bound object, derived from the governance and
    /// manifest bytes this reader decrypts. It names one object's exact governance.
    pub fn governance_hash_key(&self, view: &GovernanceView) -> Result<String> {
        Keys::new(self, view, None).hash_key()
    }

    /// Open `selected`, group names already validated against the admitted object.
    fn open_selected(
        &self,
        admitted: &AdmittedObject,
        selected: Vec<String>,
        supplied: Option<&str>,
    ) -> Result<OpenedObject> {
        self.require_bound(&admitted.view.object)?;
        self.check_strict(admitted, &selected)?;
        let mut keys = Keys::new(self, &admitted.view, supplied);
        if supplied.is_some() && admitted.view.object.bound() {
            // A supplied key must name this governance whatever groups open, the
            // manifest alone included.
            keys.hash_key()?;
        }
        let mut plaintext = BTreeMap::new();
        for name in selected {
            let fields = keys.open(&name)?;
            plaintext.insert(name, Value::Object(fields));
        }
        Ok(OpenedObject {
            admitted: admitted.clone(),
            groups: plaintext,
        })
    }

    fn check_strict(&self, admitted: &AdmittedObject, selected: &[String]) -> Result<()> {
        let Some(accepted) = &admitted.strict else {
            return Ok(());
        };
        if !Arc::ptr_eq(&self.identity, &admitted.view.reader_identity) {
            return Err(invalid("strict acceptance belongs to a different reader context"));
        }
        if selected.iter().any(|name| accepted.groups.binary_search(name).is_err()) {
            return Err(invalid("opening cannot expand the strictly accepted business groups"));
        }
        Ok(())
    }

    /// Decrypt one group under `aad`, returning its fields and its exact plaintext bytes.
    fn decrypt(
        &self,
        object: &GovernedObject,
        name: &str,
        aad: &[u8],
    ) -> Result<(Map<String, Value>, Vec<u8>)> {
        let block = object
            .groups
            .get(name)
            .ok_or_else(|| invalid(format!("object has no group {name:?}")))?;
        let mut cipher_error = None;
        for cipher in self.groups.get(name).into_iter().flatten() {
            let bytes = match cipher.decrypt_with_aad(&block.ciphertext, aad) {
                Ok(bytes) => bytes,
                Err(Error::NotEntitled { .. } | Error::NotAPublisher { .. }) => continue,
                Err(error) => {
                    cipher_error = Some(error);
                    continue;
                }
            };
            let fields = decrypted_fields(&bytes, block, object.bound())?;
            if let Some(index) = self.indexes.get(name) {
                verify_field_hashes(index, &fields, block)?;
            }
            return Ok((fields, bytes));
        }
        Err(cipher_error.unwrap_or_else(|| Error::NotEntitled {
            group: name.to_owned(),
        }))
    }
}

/// Parse decrypted group bytes. A bound object's digests cover these exact bytes,
/// so they must also be the one canonical encoding of what they say.
fn decrypted_fields(bytes: &[u8], block: &GroupBlock, bound: bool) -> Result<Map<String, Value>> {
    let source = std::str::from_utf8(bytes).map_err(|_| invalid("opened group must be UTF-8 JSON"))?;
    let value = parse_json(source)?;
    if bound && canonical_bytes(&value)? != bytes {
        return Err(invalid("a bound group's plaintext must be canonical JSON"));
    }
    let Value::Object(fields) = value else {
        return Err(invalid("opened group must be a JSON object"));
    };
    if fields.len() != block.field_hashes.len()
        || !fields.keys().all(|f| block.field_hashes.contains_key(f))
    {
        return Err(invalid("opened fields must match the group's signed field names"));
    }
    Ok(fields)
}

/// Recompute each opened field's hash under the group's index key. The writer
/// computed them from these values, so a value that differs is refused.
fn verify_field_hashes(index: &Hmac<Sha256>, fields: &Map<String, Value>, block: &GroupBlock) -> Result<()> {
    for (field, value) in fields {
        let recomputed = crate::indexing::index_token_with_template(index, field, value)?;
        // `decrypted_fields` already matched the opened names to the signed ones.
        let signed = &block.field_hashes[field];
        if !bool::from(recomputed.as_bytes().ct_eq(signed.as_bytes())) {
            return Err(invalid(format!("opened {field:?} does not match its signed field hash")));
        }
    }
    Ok(())
}
