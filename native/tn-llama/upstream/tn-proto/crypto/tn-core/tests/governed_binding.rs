//! Binding refusals: a data group decrypts only alongside its own object's exact
//! governance and manifest, whoever holds the keys and however the envelope is re-signed.

use std::sync::Arc;

use base64::Engine as _;
use serde_json::{json, Map, Value};
use tn_core::canonical::canonical_bytes;
use tn_core::cipher::{btn::BtnPublisherCipher, GroupCipher};
use tn_core::governed::{
    Governance, GovernedDraft, GovernedObject, GovernedReader, GovernedWriter, OpenedObject,
};
use tn_core::sealed_object::extract_group_blocks;
use tn_core::{DeviceKey, Result};

const POLICY: &str = "---\nversion: 1\nschema: tn-agents-policy@v1\n---\n## research.sample\n### instruction\nCreate the approved aggregate report.\n### use_for\nAggregate research.\n### do_not_use_for\nIndividual disclosure.\n### consequences\nContract review.\n### on_violation_or_error\nRefuse release.\n";

fn cipher() -> Arc<dyn GroupCipher> {
    let mut state = tn_btn::PublisherState::setup(tn_btn::Config::default()).unwrap();
    let kit = state.mint().unwrap();
    Arc::new(BtnPublisherCipher::from_state(state).with_reader_kit(&kit.to_bytes()).unwrap())
}

struct Fixture {
    device: DeviceKey,
    rules: Arc<dyn GroupCipher>,
    evidence: Arc<dyn GroupCipher>,
    values: Arc<dyn GroupCipher>,
}

impl Fixture {
    fn new() -> Self {
        Self { device: DeviceKey::generate(), rules: cipher(), evidence: cipher(), values: cipher() }
    }
    fn policy(&self) -> Governance {
        Governance::from_markdown(self.device.did(), POLICY, "agents.md", "research.sample").unwrap()
    }
    fn writer(&self) -> GovernedWriter<'_> {
        GovernedWriter::new(&self.device)
            .with_group("tn.agents", self.rules.clone(), &[1; 32]).unwrap()
            .with_group("evidence", self.evidence.clone(), &[2; 32]).unwrap()
            .with_group("values", self.values.clone(), &[3; 32]).unwrap()
    }
    fn reader(&self) -> GovernedReader {
        GovernedReader::new()
            .with_governance_index_key(&[1; 32]).unwrap()
            .with_group("tn.agents", self.rules.clone()).unwrap()
            .with_group("evidence", self.evidence.clone()).unwrap()
            .with_group("values", self.values.clone()).unwrap()
    }
    fn seal(&self, amount: i64) -> GovernedObject {
        let draft = GovernedDraft::new("research.sample", self.policy()).unwrap()
            .group("values", json!({"amount": amount})).unwrap()
            .group("evidence", json!({"manifest": {"cells": {"amount": {"row": 0}}}})).unwrap()
            .manifest("evidence").unwrap();
        self.writer().seal(draft).unwrap()
    }
    fn open(&self, reader: &GovernedReader, object: &GovernedObject, group: &str) -> Result<OpenedObject> {
        let admitted = reader.governance(object)?.authorize("inspect", |_, _| Ok(true))?;
        reader.open(&admitted, [group])
    }
    fn governance_fields(&self, object: &GovernedObject) -> Map<String, Value> {
        self.reader().governance(object).unwrap().governance().fields().clone()
    }
}

fn labels(object: &GovernedObject) -> Value {
    serde_json::from_str(object.envelope()["tn_aad"].as_str().unwrap()).unwrap()
}

/// Replace one group's ciphertext with `plaintext` encrypted under `aad`, keeping its field hashes.
fn reencrypt(env: &mut Map<String, Value>, group: &str, cipher: &Arc<dyn GroupCipher>, plaintext: &[u8], aad: &[u8]) {
    let ciphertext = cipher.encrypt_with_aad(plaintext, aad).unwrap();
    env[group]["ciphertext"] = json!(base64::engine::general_purpose::STANDARD.encode(ciphertext));
}

/// Recompute one group's field hashes for `fields` under `index_key`, as its writer would.
fn rehash(env: &mut Map<String, Value>, group: &str, fields: &Map<String, Value>, index_key: &[u8]) {
    let hashes = fields
        .iter()
        .map(|(field, value)| (field.clone(), json!(tn_core::indexing::index_token(index_key, field, value).unwrap())))
        .collect();
    env[group]["field_hashes"] = Value::Object(hashes);
}

fn resign(env: &mut Map<String, Value>, device: &DeviceKey) -> GovernedObject {
    use tn_core::chain::{compute_row_hash, GroupInput, RowHashInput};
    use tn_core::sealed_object::ENVELOPE_RESERVED;
    let blocks = extract_group_blocks(env).unwrap();
    let public = env.iter()
        .filter(|(key, _)| !ENVELOPE_RESERVED.contains(&key.as_str()) && !blocks.contains_key(*key))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let groups = blocks.into_iter()
        .map(|(name, b)| (name, GroupInput { ciphertext: b.ciphertext, field_hashes: b.field_hashes }))
        .collect();
    let row_hash = compute_row_hash(&RowHashInput {
        device_identity: env["device_identity"].as_str().unwrap(),
        timestamp: env["timestamp"].as_str().unwrap(),
        event_id: env["event_id"].as_str().unwrap(),
        event_type: env["event_type"].as_str().unwrap(),
        level: env["level"].as_str().unwrap(),
        prev_hash: env["prev_hash"].as_str().unwrap(),
        public_fields: &public,
        groups: &groups,
    });
    env.insert("signature".into(), json!(tn_core::signing::signature_b64(&device.sign(row_hash.as_bytes()))));
    env.insert("row_hash".into(), json!(row_hash));
    GovernedObject::parse(&serde_json::to_string(env).unwrap()).unwrap()
}

#[test]
fn a_bound_object_names_its_manifest_and_opens_for_a_full_reader() {
    let f = Fixture::new();
    let object = f.seal(42);
    assert!(object.bound());
    assert_eq!(object.manifest_group(), Some("evidence"));
    assert_eq!(labels(&object)["values"]["manifest"], "evidence");
    assert_eq!(labels(&object)["evidence"]["role"], "manifest");
    let reader = f.reader();
    assert_eq!(f.open(&reader, &object, "values").unwrap().groups()["values"]["amount"], 42);
    assert!(f.open(&reader, &object, "evidence").is_ok());
}

#[test]
fn governance_rewritten_under_its_own_label_opens_but_nothing_bound_to_it_does() {
    let f = Fixture::new();
    let object = f.seal(42);
    let mut fields = f.governance_fields(&object);
    fields.insert("do_not_use_for".into(), json!("Nothing."));
    let mut env = object.envelope().clone();
    let label = canonical_bytes(&labels(&object)["tn.agents"]).unwrap();
    reencrypt(&mut env, "tn.agents", &f.rules, &canonical_bytes(&json!(fields)).unwrap(), &label);
    rehash(&mut env, "tn.agents", &fields, &[1; 32]);
    let changed = resign(&mut env, &f.device);
    let reader = f.reader();
    // The holder of every key sees the rewritten rules, but cannot open the data with them.
    assert_eq!(reader.governance(&changed).unwrap().governance().get("do_not_use_for").unwrap(), "Nothing.");
    assert!(f.open(&reader, &changed, "values").is_err());
    assert!(f.open(&reader, &changed, "evidence").is_err());
}

#[test]
fn governance_rewritten_without_its_field_hashes_is_refused_on_open() {
    let f = Fixture::new();
    let object = f.seal(42);
    let mut fields = f.governance_fields(&object);
    fields.insert("do_not_use_for".into(), json!("Nothing."));
    let mut env = object.envelope().clone();
    let label = canonical_bytes(&labels(&object)["tn.agents"]).unwrap();
    reencrypt(&mut env, "tn.agents", &f.rules, &canonical_bytes(&json!(fields)).unwrap(), &label);
    let changed = resign(&mut env, &f.device);
    // The reader holds the governance index key, so it recomputes the signed field hashes.
    let error = f.reader().governance(&changed).err().unwrap();
    assert!(error.to_string().contains("signed field hash"), "{error}");
}

#[test]
fn a_governance_group_moved_from_another_object_does_not_open() {
    let f = Fixture::new();
    let (target, other) = (f.seal(1), f.seal(2));
    assert_eq!(labels(&target)["tn.agents"]["policy"], labels(&other)["tn.agents"]["policy"]);
    let mut env = target.envelope().clone();
    env["tn.agents"] = other.envelope()["tn.agents"].clone();
    let moved = resign(&mut env, &f.device);
    assert!(f.reader().governance(&moved).is_err());
}

#[test]
fn a_manifest_or_data_group_moved_from_another_object_does_not_open() {
    let f = Fixture::new();
    let (target, other) = (f.seal(1), f.seal(2));
    for group in ["evidence", "values"] {
        let mut env = target.envelope().clone();
        env[group] = other.envelope()[group].clone();
        let moved = resign(&mut env, &f.device);
        let reader = f.reader();
        assert!(f.open(&reader, &moved, "values").is_err(), "values beside a moved {group}");
        assert!(reader.governance(&moved).is_ok(), "the target's own governance still opens");
    }
}

#[test]
fn the_governance_hash_key_names_one_object_and_a_wrong_key_fails_decryption() {
    let f = Fixture::new();
    let (object, other) = (f.seal(1), f.seal(1));
    let reader = f.reader();
    let view = reader.governance(&object).unwrap();
    let key = reader.governance_hash_key(&view).unwrap();
    let other_key = reader.governance_hash_key(&reader.governance(&other).unwrap()).unwrap();
    assert!(key.starts_with("hmac-sha256:v1:") && key.len() == "hmac-sha256:v1:".len() + 64);
    assert_ne!(key, other_key, "same writer, policy, and content still name different objects");
    let admitted = view.authorize("inspect", |_, _| Ok(true)).unwrap();
    assert_eq!(reader.open_with_hash_key(&admitted, ["values"], &key).unwrap().groups()["values"]["amount"], 1);
    assert!(reader.open_with_hash_key(&admitted, ["values"], &other_key).is_err());
    assert!(reader.open_with_hash_key(&admitted, ["values"], "hmac-sha256:v1:0").is_err());
}

/// The binding digest, reimplemented from the specification rather than imported.
fn spec_digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::new().chain_update(b"tn.binding.v2.digest\0").chain_update(bytes).finalize())
}

fn original_key(f: &Fixture, object: &GovernedObject) -> String {
    let reader = f.reader();
    reader.governance_hash_key(&reader.governance(object).unwrap()).unwrap()
}

#[test]
fn a_supplied_governance_hash_key_cannot_open_data_beside_rewritten_governance() {
    let f = Fixture::new();
    let object = f.seal(42);
    let key = original_key(&f, &object);
    let mut fields = f.governance_fields(&object);
    fields.insert("do_not_use_for".into(), json!("Nothing."));
    let mut env = object.envelope().clone();
    let label = canonical_bytes(&labels(&object)["tn.agents"]).unwrap();
    reencrypt(&mut env, "tn.agents", &f.rules, &canonical_bytes(&json!(fields)).unwrap(), &label);
    rehash(&mut env, "tn.agents", &fields, &[1; 32]);
    let changed = resign(&mut env, &f.device);
    let reader = f.reader();
    let admitted = reader.governance(&changed).unwrap().authorize("inspect", |_, _| Ok(true)).unwrap();
    assert!(reader.open_with_hash_key(&admitted, ["values"], &key).is_err());
}

#[test]
fn a_supplied_governance_hash_key_cannot_open_data_beside_a_rewritten_manifest() {
    let f = Fixture::new();
    let object = f.seal(42);
    let key = original_key(&f, &object);
    let governance = canonical_bytes(&json!(f.governance_fields(&object))).unwrap();
    let aad = json!({"label": labels(&object)["evidence"], "governance_digest": spec_digest(&governance)});
    let manifest = json!({"manifest": {"cells": {"amount": {"row": 9}}}});
    let mut env = object.envelope().clone();
    reencrypt(&mut env, "evidence", &f.evidence, &canonical_bytes(&manifest).unwrap(), &canonical_bytes(&aad).unwrap());
    let changed = resign(&mut env, &f.device);
    let reader = f.reader();
    assert!(f.open(&reader, &changed, "evidence").is_ok(), "the rewritten manifest opens under the unchanged governance");
    let admitted = reader.governance(&changed).unwrap().authorize("inspect", |_, _| Ok(true)).unwrap();
    assert!(reader.open_with_hash_key(&admitted, ["values"], &key).is_err());
}

#[test]
fn a_wrong_governance_hash_key_cannot_open_the_manifest_alone() {
    let f = Fixture::new();
    let (object, other) = (f.seal(1), f.seal(1));
    let reader = f.reader();
    let other_key = original_key(&f, &other);
    let admitted = reader.governance(&object).unwrap().authorize("inspect", |_, _| Ok(true)).unwrap();
    assert!(reader.open_with_hash_key(&admitted, ["evidence"], &other_key).is_err());
    let key = original_key(&f, &object);
    assert!(reader.open_with_hash_key(&admitted, ["evidence"], &key).is_ok());
}

#[test]
fn bound_data_needs_the_governance_index_key() {
    let f = Fixture::new();
    let object = f.seal(7);
    let reader = GovernedReader::new()
        .with_group("tn.agents", f.rules.clone()).unwrap()
        .with_group("evidence", f.evidence.clone()).unwrap()
        .with_group("values", f.values.clone()).unwrap();
    assert!(reader.governance(&object).is_ok());
    assert!(f.open(&reader, &object, "values").is_err());
}

/// Rewrite a bound object into the label-only form written before binding.
fn label_only(f: &Fixture, object: &GovernedObject) -> GovernedObject {
    let marker = json!({"governed_by": f.device.did(), "policy": f.policy().policy_ref()});
    let mut env = object.envelope().clone();
    let reader = f.reader();
    for (group, cipher) in [("tn.agents", &f.rules), ("evidence", &f.evidence), ("values", &f.values)] {
        let plaintext = if group == "tn.agents" {
            json!(f.governance_fields(object))
        } else {
            f.open(&reader, object, group).unwrap().groups()[group].clone()
        };
        reencrypt(&mut env, group, cipher, &canonical_bytes(&plaintext).unwrap(), &canonical_bytes(&marker).unwrap());
    }
    let markers = json!({"evidence": marker, "tn.agents": marker, "values": marker});
    env.insert("tn_aad".into(), json!(String::from_utf8(canonical_bytes(&markers).unwrap()).unwrap()));
    resign(&mut env, &f.device)
}

#[test]
fn label_only_objects_open_only_through_an_explicit_unbound_reader() {
    let f = Fixture::new();
    let unbound = label_only(&f, &f.seal(5));
    assert!(!unbound.bound());
    assert!(f.reader().governance(&unbound).is_err());
    let legacy = f.reader().allow_unbound();
    assert_eq!(f.open(&legacy, &unbound, "values").unwrap().groups()["values"]["amount"], 5);
}

#[test]
fn an_unbound_admission_from_a_legacy_reader_does_not_open_through_a_default_reader() {
    let f = Fixture::new();
    let unbound = label_only(&f, &f.seal(5));
    let legacy = f.reader().allow_unbound();
    let admitted = legacy.governance(&unbound).unwrap().authorize("inspect", |_, _| Ok(true)).unwrap();
    assert!(f.reader().open(&admitted, ["values"]).is_err());
}

#[test]
fn noncanonical_governance_bytes_are_refused() {
    let f = Fixture::new();
    let object = f.seal(3);
    let pretty = serde_json::to_vec_pretty(&json!(f.governance_fields(&object))).unwrap();
    let mut env = object.envelope().clone();
    let label = canonical_bytes(&labels(&object)["tn.agents"]).unwrap();
    reencrypt(&mut env, "tn.agents", &f.rules, &pretty, &label);
    assert!(f.reader().governance(&resign(&mut env, &f.device)).is_err());
}
