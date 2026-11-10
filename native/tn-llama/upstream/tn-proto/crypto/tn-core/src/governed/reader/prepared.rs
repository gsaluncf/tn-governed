//! One read's preparation: AAD inputs derived once and the manifest decrypted once.
use serde_json::{Map, Value};
use subtle::ConstantTimeEq;

use super::{GovernanceView, GovernedReader};
use crate::canonical::canonical_bytes;
use crate::governed::binding::{self, Input};
use crate::governed::{invalid, GOVERNANCE_GROUP};
use crate::Result;

/// One object's groups during one open: AAD inputs derived at most once, and the
/// manifest decrypted at most once, whether it opens or only names the hash key.
pub(super) struct Keys<'a> {
    reader: &'a GovernedReader,
    view: &'a GovernanceView,
    supplied: Option<&'a str>,
    hash_key: Option<String>,
    manifest: Option<(Map<String, Value>, Vec<u8>)>,
}

impl<'a> Keys<'a> {
    pub(super) fn new(reader: &'a GovernedReader, view: &'a GovernanceView, supplied: Option<&'a str>) -> Self {
        Self { reader, view, supplied, hash_key: None, manifest: None }
    }

    /// Decrypt one selected group under its AAD.
    pub(super) fn open(&mut self, name: &str) -> Result<Map<String, Value>> {
        let view = self.view;
        let Some(bound) = &view.object.binding else {
            let aad = canonical_bytes(&Value::Object((*view.object.marker).clone()))?;
            return Ok(self.reader.decrypt(&view.object, name, &aad)?.0);
        };
        if bound.is_manifest(name) {
            return Ok(self.manifest()?.0.clone());
        }
        let hash_key = self.hash_key()?;
        let aad = bound.aad(name, Input::Data { hash_key: &hash_key })?;
        Ok(self.reader.decrypt(&view.object, name, &aad)?.0)
    }

    /// The bound manifest's fields and exact bytes, decrypted once.
    fn manifest(&mut self) -> Result<&(Map<String, Value>, Vec<u8>)> {
        if self.manifest.is_none() {
            let object = &self.view.object;
            let bound = object.binding.as_ref().expect("only a bound object has a bound manifest");
            let name = bound.manifest.as_deref().expect("asked only when a manifest is designated");
            let aad = bound.aad(name, Input::Manifest { governance_digest: self.view.digest()? })?;
            self.manifest = Some(self.reader.decrypt(object, name, &aad)?);
        }
        Ok(self.manifest.as_ref().expect("decrypted above"))
    }

    /// The governance hash key derived from the bytes this reader decrypted. A key
    /// the caller supplies only has to name the same governance; it never replaces it.
    pub(super) fn hash_key(&mut self) -> Result<String> {
        if self.hash_key.is_none() {
            let derived = self.derive()?;
            if let Some(supplied) = self.supplied {
                if !bool::from(supplied.as_bytes().ct_eq(derived.as_bytes())) {
                    return Err(invalid("the governance hash key does not name this object's governance"));
                }
            }
            self.hash_key = Some(derived);
        }
        Ok(self.hash_key.clone().expect("derived above"))
    }

    fn derive(&mut self) -> Result<String> {
        let view = self.view;
        let bound = view
            .object
            .binding
            .as_ref()
            .ok_or_else(|| invalid("an unbound object has no governance hash key"))?;
        let index = self
            .reader
            .indexes
            .get(GOVERNANCE_GROUP)
            .ok_or_else(|| invalid("bound data requires the reader's governance index key"))?;
        let manifest_digest = match &bound.manifest {
            Some(_) => Some(binding::digest(&self.manifest()?.1)),
            None => None,
        };
        Ok(binding::hash_key(index, &bound.id, view.digest()?, manifest_digest.as_deref()))
    }
}
