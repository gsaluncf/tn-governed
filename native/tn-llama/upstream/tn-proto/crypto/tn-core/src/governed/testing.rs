//! Test support: one writer and one full reader for objects that carry others.

use std::sync::Arc;

use serde_json::json;

use super::{Governance, GovernedDraft, GovernedObject, GovernedReader, GovernedWriter, UseContext};
use crate::cipher::{btn::BtnPublisherCipher, GroupCipher};

/// Every group the carry tests write.
pub(crate) const GROUPS: [&str; 6] = ["tn.agents", "g", "keep", "x", "y", "z"];

fn cipher() -> Arc<dyn GroupCipher> {
    let mut state = tn_btn::PublisherState::setup(tn_btn::Config::default()).unwrap();
    let kit = state.mint().unwrap();
    Arc::new(BtnPublisherCipher::from_state(state).with_reader_kit(&kit.to_bytes()).unwrap())
}

pub(crate) fn policy(device: &crate::DeviceKey) -> Governance {
    Governance::from_markdown(device.did(),
        "## data\n### instruction\nAnalyze.\n### use_for\nResearch.\n### do_not_use_for\nDisclosure.\n### consequences\nReview.\n### on_violation_or_error\nRefuse.\n",
        "unity/data", "data").unwrap()
}

/// The complete use every carry test admits.
pub(crate) fn usage() -> UseContext {
    UseContext::new("tests", "research", "inspect").unwrap()
}

/// One device and one cipher per group, shared by the writer and the reader.
pub(crate) struct Carry {
    device: crate::DeviceKey,
    ciphers: Vec<Arc<dyn GroupCipher>>,
}

impl Carry {
    pub(crate) fn new() -> Self {
        Self { device: crate::DeviceKey::generate(), ciphers: GROUPS.iter().map(|_| cipher()).collect() }
    }

    /// Sign an object holding `groups`, each `{"from": <group>}`, that carries `carried`.
    pub(crate) fn seal(&self, groups: &[&str], carried: Vec<GovernedObject>) -> GovernedObject {
        let mut writer = GovernedWriter::new(&self.device);
        for (name, cipher) in GROUPS.iter().zip(&self.ciphers) {
            writer = writer.with_group(name, cipher.clone(), &[1; 32]).unwrap();
        }
        let mut draft = GovernedDraft::new("data", policy(&self.device)).unwrap();
        for name in groups {
            draft = draft.group(name, json!({"from": name})).unwrap();
        }
        draft.carried = carried;
        writer.seal(draft).unwrap()
    }

    /// A reader holding every group's key and the governance index key.
    pub(crate) fn reader(&self) -> GovernedReader {
        self.reader_without(None)
    }

    /// A reader holding every group's key and index key except `missing`'s, as a
    /// runtime builds one.
    pub(crate) fn reader_without(&self, missing: Option<&str>) -> GovernedReader {
        let mut reader = GovernedReader::new();
        for (name, cipher) in GROUPS.iter().zip(&self.ciphers) {
            if Some(*name) != missing {
                reader = reader.with_group(name, cipher.clone()).unwrap();
                reader = reader.with_group_index_key(name, &[1; 32]).unwrap();
            }
        }
        reader
    }

    /// A reader holding every group's key but only the governance index key, so
    /// it checks opened data groups by field name alone.
    pub(crate) fn names_only_reader(&self) -> GovernedReader {
        let mut reader = GovernedReader::new().with_governance_index_key(&[1; 32]).unwrap();
        for (name, cipher) in GROUPS.iter().zip(&self.ciphers) {
            reader = reader.with_group(name, cipher.clone()).unwrap();
        }
        reader
    }
}
