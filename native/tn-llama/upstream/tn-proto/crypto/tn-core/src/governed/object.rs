use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use serde_json::{Map, Value};

use crate::canonical::canonical_bytes;
use crate::sealed_object::{extract_group_blocks, verify_sealed, GroupBlock, ENVELOPE_RESERVED};
use crate::{Error, Result};

use super::binding::{self, Binding, CARRIED_FIELD};
pub(super) use super::object_json::parse_json;
use super::policy::{string_field, validate_marker};
use super::{invalid, validate_group, validate_name, GOVERNANCE_GROUP};

/// Nesting limit for whole objects carried inside one another.
const MAX_CARRIED_DEPTH: usize = 32;

/// An integrity-verified governed envelope with its exact transport bytes.
///
/// Verification authenticates the writer and the carried binding. Applications
/// apply their authority and permitted-use rules when admitting the contract.
/// Parsing fixes the contents, so clones share them.
#[derive(Clone)]
pub struct GovernedObject {
    wire: Arc<str>,
    envelope: Arc<Map<String, Value>>,
    pub(super) groups: Arc<BTreeMap<String, GroupBlock>>,
    pub(super) marker: Arc<Map<String, Value>>,
    pub(super) binding: Option<Arc<Binding>>,
    carried: Arc<Vec<GovernedObject>>,
}

impl GovernedObject {
    /// Read and integrity-verify an exact publication from a byte stream.
    pub fn read(mut source: impl std::io::Read) -> Result<Self> {
        let mut wire = String::new();
        source.read_to_string(&mut wire)?;
        Self::parse(&wire)
    }
    /// Write the retained signed bytes without resealing or serialization.
    pub fn write(&self, mut destination: impl std::io::Write) -> Result<()> {
        destination.write_all(self.forward())?;
        Ok(())
    }
    /// Exact signed bytes for the application's transport.
    pub fn forward(&self) -> &[u8] {
        self.wire.as_bytes()
    }
    /// Inspect authenticated envelope metadata and encrypted group blocks.
    pub fn inspect(&self) -> &Map<String, Value> {
        self.envelope()
    }
    /// Verify a standalone object or signed emitted row and its governance AAD.
    /// The source is retained unchanged for subsequent forwarding.
    pub fn parse(wire: &str) -> Result<Self> {
        Self::parse_at(wire, 0)
    }

    fn parse_at(wire: &str, depth: usize) -> Result<Self> {
        if depth > MAX_CARRIED_DEPTH {
            return Err(invalid("carried objects are nested too deeply"));
        }
        let value = parse_json(wire)?;
        let env = value
            .as_object()
            .ok_or_else(|| invalid("envelope must be a JSON object"))?;
        let sequence = validate_header(env)?;
        let groups = extract_group_blocks(env)?;
        validate_public_shape(env, &groups)?;
        validate_groups(env, &groups)?;
        verify_envelope(env, &groups, sequence)?;
        let (binding, marker) = parse_labels(env, &groups)?;
        Ok(Self {
            wire: Arc::from(wire),
            envelope: Arc::new(env.clone()),
            groups: Arc::new(groups),
            marker: Arc::new(marker),
            binding: binding.map(Arc::new),
            carried: Arc::new(carried_objects(env, depth)?),
        })
    }

    /// Whether this object's labels are validated version 2 binding labels. This is
    /// structural: decrypting a group is what shows it is bound to this exact
    /// governance. Unbound objects carry only the label-only form written before binding.
    pub fn bound(&self) -> bool {
        self.binding.is_some()
    }

    /// Whole input objects this object carries because its writer could not open them.
    pub fn carried(&self) -> &[GovernedObject] {
        &self.carried
    }

    /// The nearest object holding `group`: this one, then the objects it carries,
    /// breadth first. Receipt opens the group from this object, so its public
    /// envelope holds the group's ciphertext and signed field hashes.
    pub fn holder(&self, group: &str) -> Option<&GovernedObject> {
        let mut pending = std::collections::VecDeque::from([self]);
        while let Some(object) = pending.pop_front() {
            if object.groups.contains_key(group) {
                return Some(object);
            }
            pending.extend(object.carried.iter());
        }
        None
    }

    /// Business groups this object or any object it carries holds, which a
    /// routed receipt can open.
    pub fn held_groups(&self) -> std::collections::BTreeSet<&str> {
        let mut held = std::collections::BTreeSet::new();
        let mut pending = vec![self];
        while let Some(object) = pending.pop() {
            held.extend(object.group_names().into_iter().filter(|name| *name != GOVERNANCE_GROUP));
            pending.extend(object.carried.iter());
        }
        held
    }

    /// The manifest group every data group of a bound object is bound to, if any.
    pub fn manifest_group(&self) -> Option<&str> {
        self.binding.as_ref().and_then(|b| b.manifest.as_deref())
    }

    /// Exact verified input, ready for transport or retention as exhaust.
    pub fn wire(&self) -> &str {
        &self.wire
    }
    /// Immutable envelope, including every opened or unopened group's ciphertext.
    pub fn envelope(&self) -> &Map<String, Value> {
        &self.envelope
    }
    /// Signed content identity of this object.
    pub fn id(&self) -> &str {
        self.verified_header("row_hash")
    }
    /// Object/event type.
    pub fn object_type(&self) -> &str {
        self.verified_header("event_type")
    }
    /// Writer whose signature was verified.
    pub fn writer(&self) -> &str {
        self.verified_header("device_identity")
    }

    fn verified_header(&self, name: &str) -> &str {
        // parse establishes these strings; callers cannot mutate the envelope.
        self.envelope[name]
            .as_str()
            .expect("verified immutable header")
    }
    /// Encrypted groups present in the object, in sorted order.
    pub fn group_names(&self) -> Vec<&str> {
        self.groups.keys().map(String::as_str).collect()
    }
}

/// Required header strings, a valid event type, and the unsigned sequence.
fn validate_header(env: &Map<String, Value>) -> Result<u64> {
    for key in [
        "device_identity",
        "timestamp",
        "event_id",
        "event_type",
        "row_hash",
        "signature",
    ] {
        string_field(env, key)?;
    }
    validate_name(string_field(env, "event_type")?)?;
    for key in ["prev_hash", "level"] {
        if !env.get(key).is_some_and(Value::is_string) {
            return Err(invalid(format!("required string {key:?}")));
        }
    }
    env.get("sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("sequence requires an unsigned integer"))
}

/// The row hash and signature over the exact envelope; a refusal names each failed check.
fn verify_envelope(
    env: &Map<String, Value>,
    groups: &BTreeMap<String, GroupBlock>,
    sequence: u64,
) -> Result<()> {
    let valid = verify_sealed(env, groups);
    if valid.signature && valid.row_hash {
        return Ok(());
    }
    let mut failed_checks = Vec::new();
    if !valid.signature {
        failed_checks.push("signature".into());
    }
    if !valid.row_hash {
        failed_checks.push("row_hash".into());
    }
    Err(Error::SealedObjectVerify {
        failed_checks,
        sequence,
        event_type: string_field(env, "event_type")?.to_owned(),
    })
}

/// The canonical `tn_aad` labels, which must name every encrypted group, read as a
/// binding and its governance marker, or as the label-only form written before binding.
fn parse_labels(
    env: &Map<String, Value>,
    groups: &BTreeMap<String, GroupBlock>,
) -> Result<(Option<Binding>, Map<String, Value>)> {
    let aad = string_field(env, "tn_aad")?;
    let aad_value = parse_json(aad)?;
    if canonical_bytes(&aad_value)? != aad.as_bytes() {
        return Err(invalid("tn_aad requires canonical JSON bytes"));
    }
    let labels = aad_value
        .as_object()
        .ok_or_else(|| invalid("tn_aad requires a group map"))?;
    if labels.len() != groups.len() || !groups.keys().all(|g| labels.contains_key(g)) {
        return Err(invalid("tn_aad must bind every encrypted group"));
    }
    let binding = binding::from_labels(env, labels)?;
    let marker = match &binding {
        Some(bound) => {
            let mut marker = Map::new();
            marker.insert("governed_by".into(), Value::from(bound.governed_by.as_str()));
            marker.insert("policy".into(), Value::from(bound.policy.as_str()));
            marker
        }
        None => unbound_marker(labels)?,
    };
    Ok((binding, marker))
}

/// The label-only form: one identical `{governed_by, policy}` marker on every group.
fn unbound_marker(labels: &Map<String, Value>) -> Result<Map<String, Value>> {
    let marker = labels[GOVERNANCE_GROUP]
        .as_object()
        .ok_or_else(|| invalid("governance marker requires an object"))?;
    if marker.len() != 2 {
        return Err(invalid("governance marker requires governed_by and policy"));
    }
    validate_marker(string_field(marker, "governed_by")?, string_field(marker, "policy")?)?;
    if !labels.values().all(|value| value.as_object() == Some(marker)) {
        return Err(invalid("all encrypted groups must carry the same governance marker"));
    }
    Ok(marker.clone())
}

/// Parse and verify every whole object carried in the signed public metadata.
fn carried_objects(env: &Map<String, Value>, depth: usize) -> Result<Vec<GovernedObject>> {
    let Some(field) = env.get(CARRIED_FIELD) else {
        return Ok(Vec::new());
    };
    let text = field
        .as_str()
        .ok_or_else(|| invalid("tn_carried requires a string"))?;
    let value = parse_json(text)?;
    if canonical_bytes(&value)? != text.as_bytes() {
        return Err(invalid("tn_carried requires canonical JSON bytes"));
    }
    let wires = value
        .as_array()
        .filter(|wires| !wires.is_empty())
        .ok_or_else(|| invalid("tn_carried requires a nonempty list"))?;
    wires
        .iter()
        .map(|wire| {
            let wire = wire.as_str().ok_or_else(|| invalid("carried objects are wire strings"))?;
            GovernedObject::parse_at(wire, depth + 1)
        })
        .collect()
}

fn validate_groups(env: &Map<String, Value>, groups: &BTreeMap<String, GroupBlock>) -> Result<()> {
    if !groups.contains_key(GOVERNANCE_GROUP) {
        return Err(invalid("required encrypted tn.agents group"));
    }
    for name in groups.keys() {
        validate_group(name)?;
        let block = env[name]
            .as_object()
            .ok_or_else(|| invalid("group requires an object"))?;
        if block.len() != 2 || !block.get("field_hashes").is_some_and(Value::is_object) {
            return Err(invalid("group requires ciphertext and field_hashes"));
        }
        for (field, token) in &groups[name].field_hashes {
            super::validate_field(field)?;
            let digest = token
                .strip_prefix(crate::indexing::INDEX_TOKEN_PREFIX)
                .ok_or_else(|| invalid("field hash requires an HMAC-SHA256 v1 token"))?;
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(invalid("field hash requires a lowercase SHA-256 digest"));
            }
        }
    }
    Ok(())
}

// The TN hash preimage retains the established wire encoding. The governed
// interface fixes public types and delimiters so its admitted interpretation
// is unique; typed business values belong in encrypted group JSON.
fn validate_public_shape(
    env: &Map<String, Value>,
    groups: &BTreeMap<String, GroupBlock>,
) -> Result<()> {
    for key in ENVELOPE_RESERVED {
        if env
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|s| s.contains('\0'))
        {
            return Err(invalid("envelope strings must exclude NUL delimiters"));
        }
    }
    for (key, value) in env {
        if ENVELOPE_RESERVED.contains(&key.as_str()) || groups.contains_key(key) {
            continue;
        }
        if key == "tn_sealed" {
            if value.as_u64() != Some(1) {
                return Err(invalid("tn_sealed requires integer 1"));
            }
        } else {
            validate_name(key)?;
            if value.as_str().is_none_or(|s| s.contains('\0')) {
                return Err(invalid("public metadata requires NUL-free strings; assign typed data to encrypted groups"));
            }
        }
    }
    Ok(())
}

impl fmt::Debug for GovernedObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GovernedObject")
            .field("id", &self.id())
            .field("object_type", &self.object_type())
            .field("groups", &self.group_names())
            .finish()
    }
}

impl fmt::Display for GovernedObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.wire())
    }
}
