//! Export retained M1 test publications, or replay their native acceptance checks.
mod export;
mod replay;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use tn_core::cipher::{btn::BtnPublisherCipher, btn::BtnReaderCipher, GroupCipher};
use tn_core::governed::*;
use tn_core::{DeviceKey, Result};

const SCHEMA: &str = "tn-governed-m1-fixtures@v1";
const CEREMONY: &str = "cer_governed_m1_test_fixture";
const GROUPS: [&str; 5] = [
    "tn.agents",
    "policy_revision",
    "dataset_edition",
    "finance",
    "audit",
];
const POLICY: &str = "---\nversion: 1\nschema: tn-agents-policy@v1\n---\n## finance.wealth_path\n### instruction\nCalculate approved portfolio drawdown.\n### use_for\nPortfolio research.\n### do_not_use_for\nIndividual disclosure.\n### consequences\nReview.\n### on_violation_or_error\nRefuse.\n";
const TEST_SEED: [u8; 32] = [0x51; 32];
const INDEX_MASTER: [u8; 32] = [0x37; 32];

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupMaterial {
    publisher_state_base64: String,
    reader_kit_base64: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Publication {
    object_id: String,
    writer: String,
    object_type: String,
    wire: String,
}

impl From<&GovernedObject> for Publication {
    fn from(object: &GovernedObject) -> Self {
        Self {
            object_id: object.id().into(),
            writer: object.writer().into(),
            object_type: object.object_type().into(),
            wire: object.wire().into(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    publication: String,
    selection: Option<String>,
    use_name: String,
    groups: Vec<String>,
    decision: String,
    allowed: bool,
    decision_calls: usize,
    business_decrypts: usize,
    error_contains: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedRelease {
    contracts: Vec<String>,
    dataset_bindings: Vec<DatasetBinding>,
    parent_ids: Vec<String>,
    lineage_object_ids: Vec<String>,
    finance: Value,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    test_only: bool,
    producer: Value,
    private_seed_hex: String,
    index_master_hex: String,
    writer: String,
    groups: BTreeMap<String, GroupMaterial>,
    uses: BTreeMap<String, UseContext>,
    publications: BTreeMap<String, Publication>,
    expected_releases: BTreeMap<String, ExpectedRelease>,
    cases: Vec<Case>,
}

fn writer<'a>(
    device: &'a DeviceKey,
    groups: &BTreeMap<String, GroupMaterial>,
) -> Result<GovernedWriter<'a>> {
    let mut writer = GovernedWriter::new(device);
    for name in GROUPS {
        let group = &groups[name];
        let cipher = BtnPublisherCipher::from_state_bytes(
            &STANDARD.decode(&group.publisher_state_base64).unwrap(),
        )?
        .with_reader_kit(&STANDARD.decode(&group.reader_kit_base64).unwrap())?;
        let index = tn_core::indexing::derive_group_index_key(&INDEX_MASTER, CEREMONY, name, 0)?;
        writer = writer.with_group(name, Arc::new(cipher), &index)?;
    }
    Ok(writer)
}

struct Probe {
    inner: BtnReaderCipher,
    calls: Arc<AtomicUsize>,
}
impl GroupCipher for Probe {
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }
    fn encrypt(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        self.inner.encrypt(bytes)
    }
    fn decrypt(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.decrypt(bytes)
    }
    fn encrypt_with_aad(&self, bytes: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.inner.encrypt_with_aad(bytes, aad)
    }
    fn decrypt_with_aad(&self, bytes: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.decrypt_with_aad(bytes, aad)
    }
}

fn reader(groups: &BTreeMap<String, GroupMaterial>) -> Result<(GovernedReader, Arc<AtomicUsize>)> {
    let business = Arc::new(AtomicUsize::new(0));
    let mut reader = GovernedReader::new();
    for name in GROUPS {
        let cipher = BtnReaderCipher::from_kit_bytes(
            &STANDARD.decode(&groups[name].reader_kit_base64).unwrap(),
        )?;
        let counter = if matches!(name, "finance" | "audit") {
            business.clone()
        } else {
            Arc::new(AtomicUsize::new(0))
        };
        reader = reader.with_group(
            name,
            Arc::new(Probe {
                inner: cipher,
                calls: counter,
            }),
        )?;
        // The writer's index keys: bound data needs the governance one, and each
        // group's own lets the reader recompute its field hashes on open.
        let index = tn_core::indexing::derive_group_index_key(&INDEX_MASTER, CEREMONY, name, 0)?;
        reader = reader.with_group_index_key(name, &index)?;
    }
    Ok((reader, business))
}

fn metadata(reader: &GovernedReader, object: &GovernedObject, group: &str) -> Result<OpenedObject> {
    let admitted = reader.governance(object)?.accept(
        UseContext::new("fixture.catalog", "administration", "inspect")?,
        [group],
        |_| Ok(true),
    )?;
    reader.open(&admitted, [group])
}

fn materialize(
    manifest: &Manifest,
    directory: &Path,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    replay::verify(manifest)?;
    // Require a fresh named directory; never replace an existing session's material.
    std::fs::create_dir(directory)?;
    let keys = directory.join("keys");
    std::fs::create_dir(&keys)?;
    std::fs::write(keys.join("local.private"), TEST_SEED)?;
    std::fs::write(keys.join("index_master.key"), INDEX_MASTER)?;
    for name in GROUPS {
        std::fs::write(
            keys.join(format!("{name}.btn.state")),
            STANDARD.decode(&manifest.groups[name].publisher_state_base64)?,
        )?;
        std::fs::write(
            keys.join(format!("{name}.btn.mykit")),
            STANDARD.decode(&manifest.groups[name].reader_kit_base64)?,
        )?;
    }
    let groups: BTreeMap<_, _> = GROUPS
        .iter()
        .map(|name| {
            (
                *name,
                json!({"cipher":"btn", "policy":"private", "index_epoch":0}),
            )
        })
        .collect();
    let config = json!({"ceremony":{"id":CEREMONY, "cipher":"btn", "mode":"local"},
        "keystore":{"path":"keys"}, "device":{"device_identity":manifest.writer}, "groups":groups});
    std::fs::write(
        directory.join("tn.yaml"),
        serde_json::to_vec_pretty(&config)?,
    )?;
    std::fs::write(directory.join("tn.agents.md"), POLICY)?;
    let session = tn_core::runtime::Objects::open(&directory.join("tn.yaml"))?;
    let source = &manifest.publications["source_earlier"];
    let opened = session.receive_for(
        &source.wire,
        &manifest.uses["source"],
        ["finance"],
        None,
        |_| Ok(true),
    )?;
    assert_eq!(
        opened.group("finance").unwrap()["wealth_path"],
        json!([100, 120, 90, 135])
    );
    Ok(())
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.as_slice() {
        [_] => { let manifest = export::export()?; replay::verify(&manifest)?; println!("{}", serde_json::to_string_pretty(&manifest)?); }
        [_, flag, path] if flag == "--export" => {
            let manifest = export::export()?;
            replay::verify(&manifest)?;
            std::fs::write(path, format!("{}\n", serde_json::to_string_pretty(&manifest)?))?;
            println!("Exported and verified {} publications and {} admission cases.", manifest.publications.len(), manifest.cases.len());
        }
        [_, flag, path] if flag == "--verify" => {
            let manifest: Manifest = serde_json::from_slice(&std::fs::read(path)?)?;
            replay::verify(&manifest)?;
            println!("Verified {} exact publications, {} release graphs and {} admission cases.", manifest.publications.len(), manifest.expected_releases.len(), manifest.cases.len());
        }
        [_, flag, path, directory] if flag == "--materialize" => {
            let manifest = serde_json::from_slice(&std::fs::read(path)?)?;
            materialize(&manifest, Path::new(directory))?;
            println!("Materialized and reopened the test session at {directory}.");
        }
        _ => return Err("usage: governed_fixture_manifest [--export manifest.json | --verify manifest.json | --materialize manifest.json NEW_DIRECTORY]".into()),
    }
    Ok(())
}
