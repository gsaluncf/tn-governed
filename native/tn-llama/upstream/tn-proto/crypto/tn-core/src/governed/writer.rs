use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hmac::Hmac;
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::Sha256;

use crate::canonical::canonical_bytes;
use crate::chain::{compute_row_hash, GroupInput, RowHashInput};
use crate::cipher::{GroupCipher, PublicationCapability};
use crate::envelope::{build_envelope, EnvelopeInput, GroupPayload};
use crate::indexing::{build_hmac_template, index_token_with_template};
use crate::{DeviceKey, Result};

use super::binding::{self, Binding, Input, CARRIED_FIELD};
use super::{invalid, validate_group, validate_name, Governance, GovernedObject, GOVERNANCE_GROUP};

/// Data and its contract before encryption. Group assignment is explicit.
#[derive(Debug, Clone)]
pub struct GovernedDraft {
    pub(super) object_type: String,
    pub(super) governance: Governance,
    groups: BTreeMap<String, Map<String, Value>>,
    pub(super) manifest: Option<String>,
    /// Whole input objects whose groups this writer could not open.
    pub(super) carried: Vec<GovernedObject>,
}

impl GovernedDraft {
    /// Create a draft with its required use contract.
    pub fn new(object_type: &str, governance: Governance) -> Result<Self> {
        validate_name(object_type)?;
        Ok(Self {
            object_type: object_type.to_owned(),
            governance,
            groups: BTreeMap::new(),
            manifest: None,
            carried: Vec::new(),
        })
    }

    /// Declare the draft's causal inputs exactly as given. Like [`Self::new`], this
    /// signs what it is told: it keeps none of a source's contracts or dataset
    /// bindings. A working copy ([`super::DataObject`]) is the path that does.
    pub fn with_source_lineage(mut self, sources: &[super::SourceReference]) -> Result<Self> {
        self.governance
            .fields
            .insert("source_lineage".to_owned(), serde_json::to_value(sources)?);
        Ok(self)
    }

    /// Name the supplied business group whose exact bytes every data group is bound to.
    pub fn manifest(mut self, name: &str) -> Result<Self> {
        validate_group(name)?;
        if name == GOVERNANCE_GROUP {
            return Err(invalid("the governance group cannot be the manifest"));
        }
        self.manifest = Some(name.to_owned());
        Ok(self)
    }

    /// Assign a JSON object of fields to an encrypted business group.
    /// `tn.agents` is populated from the contract by the writer.
    pub fn group(mut self, name: &str, fields: impl Serialize) -> Result<Self> {
        validate_group(name)?;
        if name == GOVERNANCE_GROUP || self.groups.contains_key(name) {
            return Err(invalid(format!(
                "group {name:?} already supplied or reserved for governance"
            )));
        }
        let value = serde_json::to_value(fields)?;
        let fields = value
            .as_object()
            .ok_or_else(|| invalid("group fields must be a JSON object"))?;
        for field in fields.keys() {
            super::validate_field(field)?;
        }
        self.groups.insert(name.to_owned(), fields.clone());
        Ok(self)
    }

    /// Contract selected for this draft.
    pub fn governance(&self) -> &Governance {
        &self.governance
    }
}

struct GroupSealer {
    cipher: Arc<dyn GroupCipher>,
    index: Hmac<Sha256>,
}

/// Encrypted groups and their labels, ready for signing.
#[derive(Default)]
struct Sealed {
    inputs: BTreeMap<String, GroupInput>,
    payloads: BTreeMap<String, String>,
    labels: Map<String, Value>,
}

/// Publication readiness for a set of output groups, including `tn.agents`.
///
/// Every list is sorted and deduplicated. Missing groups have no writer
/// material; unavailable groups explicitly cannot publish; unknown groups use
/// cipher implementations that do not declare their publication capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationReport {
    required: Vec<String>,
    supported: Vec<String>,
    missing: Vec<String>,
    unavailable: Vec<String>,
    unknown: Vec<String>,
}

impl PublicationReport {
    /// Requested groups plus the automatically required governance group.
    pub fn required_groups(&self) -> &[String] {
        &self.required
    }

    /// Groups whose loaded cipher material explicitly supports publication.
    pub fn supported_groups(&self) -> &[String] {
        &self.supported
    }

    /// Groups for which this writer has no material.
    pub fn missing_groups(&self) -> &[String] {
        &self.missing
    }

    /// Groups whose loaded cipher cannot publish.
    pub fn unavailable_groups(&self) -> &[String] {
        &self.unavailable
    }

    /// Groups whose cipher does not declare its publication capability.
    pub fn unknown_groups(&self) -> &[String] {
        &self.unknown
    }

    /// Whether all required groups explicitly support publication.
    pub fn is_ready(&self) -> bool {
        self.missing.is_empty() && self.unavailable.is_empty() && self.unknown.is_empty()
    }
}

/// Seals governed objects using the writer identity and group cipher material.
///
/// No logging configuration or filesystem is required. Each call returns an
/// independently signed object; the caller chooses its transport and storage.
pub struct GovernedWriter<'a> {
    device: &'a DeviceKey,
    groups: BTreeMap<String, GroupSealer>,
}

impl<'a> GovernedWriter<'a> {
    /// Identity that signs objects released by this writer.
    pub fn did(&self) -> &str {
        self.device.did()
    }
    /// Use an existing signing identity.
    pub fn new(device: &'a DeviceKey) -> Self {
        Self {
            device,
            groups: BTreeMap::new(),
        }
    }

    /// Inspect every required output group without encrypting a trial payload.
    /// `tn.agents` is always included, even when `names` is empty. Malformed or
    /// reserved names return an error; missing and unusable material is listed
    /// in the report so callers can fix the complete configuration at startup.
    pub fn check_groups<I, S>(&self, names: I) -> Result<PublicationReport>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut required = BTreeSet::from([GOVERNANCE_GROUP.to_owned()]);
        for name in names {
            let name = name.as_ref();
            validate_group(name)?;
            required.insert(name.to_owned());
        }
        let mut report = PublicationReport {
            required: required.into_iter().collect(),
            supported: Vec::new(),
            missing: Vec::new(),
            unavailable: Vec::new(),
            unknown: Vec::new(),
        };
        for name in &report.required {
            let Some(group) = self.groups.get(name) else {
                report.missing.push(name.clone());
                continue;
            };
            match group.cipher.publication_capability() {
                PublicationCapability::Supported => report.supported.push(name.clone()),
                PublicationCapability::Unsupported => report.unavailable.push(name.clone()),
                PublicationCapability::Unknown => report.unknown.push(name.clone()),
            }
        }
        Ok(report)
    }

    /// Require known publication material for every named group and `tn.agents`.
    ///
    /// This explicit startup check rejects missing, unavailable, and unknown
    /// material together. Existing custom ciphers with unknown capability can
    /// still be attached and used by [`Self::seal`] without this strict check.
    pub fn require_groups<I, S>(&self, names: I) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let report = self.check_groups(names)?;
        if report.is_ready() {
            return Ok(());
        }
        Err(crate::Error::InvalidConfig(format!(
            "publication preflight failed: missing={:?}; unavailable={:?}; unknown={:?}",
            report.missing, report.unavailable, report.unknown
        )))
    }

    /// Attach a group's encryption cipher and its separate derived index key.
    pub fn with_group(
        self,
        name: &str,
        cipher: Arc<dyn GroupCipher>,
        index_key: &[u8],
    ) -> Result<Self> {
        self.with_material(name, cipher, build_hmac_template(index_key)?)
    }

    pub(crate) fn with_material(
        mut self,
        name: &str,
        cipher: Arc<dyn GroupCipher>,
        index: Hmac<Sha256>,
    ) -> Result<Self> {
        validate_group(name)?;
        if self.groups.contains_key(name) {
            return Err(invalid(format!("duplicate writer group {name:?}")));
        }
        self.groups
            .insert(name.to_owned(), GroupSealer { cipher, index });
        Ok(self)
    }

    /// Encrypt governance, then the manifest bound to it, then data bound to both, and sign.
    ///
    /// Groups this writer could not open are never copied: their whole source
    /// objects travel in `tn_carried`, each still bound to its own governance.
    pub fn seal(&self, mut draft: GovernedDraft) -> Result<GovernedObject> {
        draft
            .groups
            .insert(GOVERNANCE_GROUP.to_owned(), draft.governance.fields.clone());
        self.require_material(&draft)?;
        let binding = Binding {
            id: uuid::Uuid::new_v4().to_string(),
            writer: self.device.did().to_owned(),
            object_type: draft.object_type.clone(),
            governed_by: draft.governance.governed_by().to_owned(),
            policy: draft.governance.policy_ref().to_owned(),
            manifest: draft.manifest.clone(),
        };
        let sealed = self.encrypt(&binding, &draft.groups)?;
        self.sign(&draft, &binding, sealed)
    }

    fn require_material(&self, draft: &GovernedDraft) -> Result<()> {
        for name in draft.groups.keys() {
            if !self.groups.contains_key(name) {
                return Err(invalid(format!("writer requires cipher material for {name:?}")));
            }
        }
        match &draft.manifest {
            Some(name) if !draft.groups.contains_key(name) => Err(invalid(format!(
                "manifest {name:?} must be a business group this writer encrypts"
            ))),
            _ => Ok(()),
        }
    }

    fn encrypt(
        &self,
        binding: &Binding,
        groups: &BTreeMap<String, Map<String, Value>>,
    ) -> Result<Sealed> {
        let mut sealed = Sealed::default();
        let governance = &groups[GOVERNANCE_GROUP];
        let bytes = canonical_bytes(&Value::Object(governance.clone()))?;
        let governance_digest = binding::digest(&bytes);
        self.encrypt_group(&mut sealed, binding, GOVERNANCE_GROUP, governance, &bytes, Input::Governance)?;
        let mut manifest_digest = None;
        if let Some(name) = &binding.manifest {
            let bytes = canonical_bytes(&Value::Object(groups[name].clone()))?;
            let input = Input::Manifest { governance_digest: &governance_digest };
            self.encrypt_group(&mut sealed, binding, name, &groups[name], &bytes, input)?;
            manifest_digest = Some(binding::digest(&bytes));
        }
        let index = &self.groups[GOVERNANCE_GROUP].index;
        let hash_key = binding::hash_key(index, &binding.id, &governance_digest, manifest_digest.as_deref());
        for (name, fields) in groups {
            if name != GOVERNANCE_GROUP && !binding.is_manifest(name) {
                let bytes = canonical_bytes(&Value::Object(fields.clone()))?;
                let input = Input::Data { hash_key: &hash_key };
                self.encrypt_group(&mut sealed, binding, name, fields, &bytes, input)?;
            }
        }
        Ok(sealed)
    }

    fn encrypt_group(
        &self,
        sealed: &mut Sealed,
        binding: &Binding,
        name: &str,
        fields: &Map<String, Value>,
        plaintext: &[u8],
        input: Input<'_>,
    ) -> Result<()> {
        let group = &self.groups[name];
        let mut field_hashes = BTreeMap::new();
        for (field, value) in fields {
            field_hashes.insert(field.clone(), index_token_with_template(&group.index, field, value)?);
        }
        let ciphertext = group.cipher.encrypt_with_aad(plaintext, &binding.aad(name, input)?)?;
        let payload = serde_json::to_string(&GroupPayload {
            ciphertext: ciphertext.clone(),
            field_hashes: field_hashes.clone(),
        })?;
        sealed.inputs.insert(name.to_owned(), GroupInput { ciphertext, field_hashes });
        sealed.payloads.insert(name.to_owned(), payload);
        sealed.labels.insert(name.to_owned(), Value::Object(binding.label(name)));
        Ok(())
    }

    fn sign(&self, draft: &GovernedDraft, binding: &Binding, sealed: Sealed) -> Result<GovernedObject> {
        let public = public_fields(&sealed.labels, &draft.carried)?;
        let timestamp = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|_| invalid("timestamp formatting failed"))?;
        let public_hash = public.clone().into_iter().collect();
        let row_hash = compute_row_hash(&RowHashInput {
            device_identity: self.device.did(),
            timestamp: &timestamp,
            event_id: &binding.id,
            event_type: &draft.object_type,
            level: "",
            prev_hash: "",
            public_fields: &public_hash,
            groups: &sealed.inputs,
        });
        let signature = crate::signing::signature_b64(&self.device.sign(row_hash.as_bytes()));
        let mut wire = build_envelope(EnvelopeInput {
            device_identity: self.device.did(),
            timestamp: &timestamp,
            event_id: &binding.id,
            event_type: &draft.object_type,
            level: "",
            sequence: 0,
            prev_hash: "",
            row_hash: &row_hash,
            signature_b64: &signature,
            public_fields: public,
            group_payloads: sealed.payloads,
        })?;
        if wire.ends_with('\n') {
            wire.pop();
        }
        GovernedObject::parse(&wire)
    }
}

/// Signed public metadata: the labels, and any whole carried input objects.
fn public_fields(labels: &Map<String, Value>, carried: &[GovernedObject]) -> Result<Map<String, Value>> {
    let text = |value: &Value| -> Result<Value> {
        String::from_utf8(canonical_bytes(value)?)
            .map(Value::String)
            .map_err(|_| invalid("canonical public metadata must be UTF-8"))
    };
    let mut public = Map::new();
    public.insert("tn_sealed".to_owned(), Value::from(1));
    public.insert("tn_aad".to_owned(), text(&Value::Object(labels.clone()))?);
    if !carried.is_empty() {
        let wires = carried.iter().map(|object| Value::from(object.wire())).collect();
        public.insert(CARRIED_FIELD.to_owned(), text(&Value::Array(wires))?);
    }
    Ok(public)
}
