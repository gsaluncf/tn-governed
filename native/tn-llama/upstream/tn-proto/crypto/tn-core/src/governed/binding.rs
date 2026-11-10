//! Binding: each encrypted group decrypts only alongside its object's exact governance.
//!
//! A bound object opens in a fixed order. `tn.agents` decrypts under its label.
//! An optional manifest group decrypts under its label plus the digest of the
//! exact governance bytes. Every other business group decrypts under its label
//! plus the governance hash key, an HMAC over the binding id and both digests.
//! Readers compute the digests from the bytes they decrypted, never from a
//! stored copy, so a changed governance or manifest leaves the data closed.

use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::canonical::canonical_bytes;
use crate::indexing::INDEX_TOKEN_PREFIX;
use crate::Result;

use super::policy::{string_field, validate_marker};
use super::{invalid, GOVERNANCE_GROUP};

/// Label version written for bound objects.
pub(super) const VERSION: u64 = 2;
/// Public field carrying whole input objects whose groups a writer could not open.
pub(super) const CARRIED_FIELD: &str = "tn_carried";
const DIGEST_DOMAIN: &[u8] = b"tn.binding.v2.digest\0";
const HASH_KEY_DOMAIN: &[u8] = b"tn.binding.v2.governance-hash-key\0";
const ROLE_GOVERNANCE: &str = "governance";
const ROLE_MANIFEST: &str = "manifest";
const ROLE_DATA: &str = "data";

/// Signed public facts that every group label of one bound object repeats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Binding {
    pub(super) id: String,
    pub(super) writer: String,
    pub(super) object_type: String,
    pub(super) governed_by: String,
    pub(super) policy: String,
    pub(super) manifest: Option<String>,
}

/// What a group's AAD adds to its label.
pub(super) enum Input<'a> {
    Governance,
    Manifest { governance_digest: &'a str },
    Data { hash_key: &'a str },
}

impl Binding {
    fn role(&self, group: &str) -> &'static str {
        if group == GOVERNANCE_GROUP {
            ROLE_GOVERNANCE
        } else if self.is_manifest(group) {
            ROLE_MANIFEST
        } else {
            ROLE_DATA
        }
    }

    /// Whether `group` is this object's manifest group.
    pub(super) fn is_manifest(&self, group: &str) -> bool {
        self.manifest.as_deref() == Some(group)
    }

    /// The signed public label for one group, repeated in `tn_aad`.
    pub(super) fn label(&self, group: &str) -> Map<String, Value> {
        let role = self.role(group);
        let mut label = Map::new();
        label.insert("binding".into(), Value::from(VERSION));
        label.insert("binding_id".into(), Value::from(self.id.as_str()));
        label.insert("governed_by".into(), Value::from(self.governed_by.as_str()));
        label.insert("policy".into(), Value::from(self.policy.as_str()));
        label.insert("writer".into(), Value::from(self.writer.as_str()));
        label.insert("object_type".into(), Value::from(self.object_type.as_str()));
        label.insert("group".into(), Value::from(group));
        label.insert("role".into(), Value::from(role));
        if let (ROLE_DATA, Some(manifest)) = (role, &self.manifest) {
            label.insert("manifest".into(), Value::from(manifest.as_str()));
        }
        label
    }

    /// Exact AAD bytes for one group; the input must match the group's role.
    pub(super) fn aad(&self, group: &str, input: Input<'_>) -> Result<Vec<u8>> {
        let label = Value::Object(self.label(group));
        let value = match (self.role(group), input) {
            (ROLE_GOVERNANCE, Input::Governance) => label,
            (ROLE_MANIFEST, Input::Manifest { governance_digest }) => {
                json!({"label": label, "governance_digest": governance_digest})
            }
            (ROLE_DATA, Input::Data { hash_key }) => {
                json!({"label": label, "governance_hash_key": hash_key})
            }
            _ => return Err(invalid(format!("group {group:?} received another role's binding input"))),
        };
        canonical_bytes(&value)
    }
}

/// Digest of the exact decrypted bytes of one group.
pub(super) fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// The governance hash key: names one object's exact governance and manifest.
pub(super) fn hash_key(
    index: &Hmac<Sha256>,
    binding_id: &str,
    governance_digest: &str,
    manifest_digest: Option<&str>,
) -> String {
    let mut mac = index.clone();
    for part in [HASH_KEY_DOMAIN, binding_id.as_bytes(), b"\0", governance_digest.as_bytes(), b"\0"] {
        mac.update(part);
    }
    mac.update(manifest_digest.unwrap_or("").as_bytes());
    format!("{INDEX_TOKEN_PREFIX}{}", hex::encode(mac.finalize().into_bytes()))
}

/// Read a bound object's labels, or `None` for an object carrying the label-only form.
pub(super) fn from_labels(
    env: &Map<String, Value>,
    labels: &Map<String, Value>,
) -> Result<Option<Binding>> {
    let governance = labels[GOVERNANCE_GROUP]
        .as_object()
        .ok_or_else(|| invalid("governance label requires an object"))?;
    if !governance.contains_key("binding") {
        return Ok(None);
    }
    let binding = Binding {
        id: string_field(governance, "binding_id")?.to_owned(),
        writer: string_field(governance, "writer")?.to_owned(),
        object_type: string_field(governance, "object_type")?.to_owned(),
        governed_by: string_field(governance, "governed_by")?.to_owned(),
        policy: string_field(governance, "policy")?.to_owned(),
        manifest: manifest_group(labels)?,
    };
    validate_marker(&binding.governed_by, &binding.policy)?;
    check_header(&binding, env)?;
    for (group, label) in labels {
        if label.as_object() != Some(&binding.label(group)) {
            return Err(invalid(format!("group {group:?} label does not match its object's binding")));
        }
    }
    Ok(Some(binding))
}

fn check_header(binding: &Binding, env: &Map<String, Value>) -> Result<()> {
    if binding.id != string_field(env, "event_id")?
        || binding.writer != string_field(env, "device_identity")?
        || binding.object_type != string_field(env, "event_type")?
    {
        return Err(invalid("binding label must name this object's event id, writer, and type"));
    }
    Ok(())
}

fn manifest_group(labels: &Map<String, Value>) -> Result<Option<String>> {
    let mut found = None;
    for (group, label) in labels {
        let role = label.get("role").and_then(Value::as_str);
        if role == Some(ROLE_MANIFEST) && found.replace(group.clone()).is_some() {
            return Err(invalid("a bound object has at most one manifest group"));
        }
    }
    if found.as_deref() == Some(GOVERNANCE_GROUP) {
        return Err(invalid("the governance group cannot be the manifest"));
    }
    Ok(found)
}
