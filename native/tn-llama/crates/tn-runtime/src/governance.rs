use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{AdmissionStage, TnLlamaError};

pub(crate) const GOVERNANCE_GROUP: &str = "tn.agents";
pub const GOVERNANCE_FIELDS: [&str; 6] = [
    "consequences",
    "do_not_use_for",
    "instruction",
    "on_violation_or_error",
    "policy",
    "use_for",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernanceKeyProvenance {
    pub ceremony_id: String,
    pub group: String,
    pub index_epoch: u64,
}

impl GovernanceKeyProvenance {
    #[must_use]
    pub fn new(ceremony_id: impl Into<String>, group: impl Into<String>, index_epoch: u64) -> Self {
        Self {
            ceremony_id: ceremony_id.into(),
            group: group.into(),
            index_epoch,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedGovernance {
    pub plaintext: BTreeMap<String, Value>,
    pub commitments: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedGroup {
    pub name: String,
    pub plaintext: BTreeMap<String, Value>,
    pub commitments: BTreeMap<String, String>,
}

pub struct GovernanceReader {
    index_master_key: Zeroizing<[u8; 32]>,
    provenance: GovernanceKeyProvenance,
    index_key_digest: String,
}

impl GovernanceReader {
    pub fn from_paths(
        reader_dir: &Path,
        index_key_path: &Path,
        provenance: GovernanceKeyProvenance,
    ) -> Result<Self, TnLlamaError> {
        if provenance.ceremony_id.trim().is_empty()
            || provenance.group != GOVERNANCE_GROUP
            || provenance.index_epoch != 0
        {
            return Err(governance_error(
                "governance_provenance_invalid",
                "version 1 requires a nonempty ceremony, tn.agents, and index epoch 0",
            ));
        }
        validate_reader_directory(reader_dir)?;

        let key_bytes = Zeroizing::new(fs::read(index_key_path).map_err(|_| {
            governance_error(
                "governance_index_key_invalid",
                "governance index key could not be read",
            )
        })?);
        if key_bytes.len() != 32 {
            return Err(governance_error(
                "governance_index_key_invalid",
                "governance index key must contain exactly 32 bytes",
            ));
        }
        let mut index_master_key = Zeroizing::new([0_u8; 32]);
        index_master_key.copy_from_slice(&key_bytes);
        let index_key_digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(index_master_key.as_slice())),
        );

        Ok(Self {
            index_master_key,
            provenance,
            index_key_digest,
        })
    }

    /// One group's index key under this reader's ceremony and epoch.
    pub(crate) fn group_index_key(&self, group: &str) -> Result<[u8; 32], TnLlamaError> {
        tn_core::indexing::derive_group_index_key(
            &*self.index_master_key,
            &self.provenance.ceremony_id,
            group,
            self.provenance.index_epoch,
        )
        .map_err(|_| {
            governance_error(
                "protected_group_commitment_compute_failed",
                "official group commitment key derivation failed",
            )
        })
    }

    #[must_use]
    pub fn index_key_digest(&self) -> &str {
        &self.index_key_digest
    }

    #[must_use]
    pub const fn provenance(&self) -> &GovernanceKeyProvenance {
        &self.provenance
    }
}

/// A native object's signed field hashes for one group, as its envelope carries them.
/// The core reader that opened the group already checked them against its plaintext.
pub(crate) fn field_hashes(
    object: &tn_core::governed::GovernedObject,
    group: &str,
) -> Result<BTreeMap<String, String>, TnLlamaError> {
    let commitments = object
        .envelope()
        .get(group)
        .and_then(|block| block.get("field_hashes"))
        .cloned()
        .ok_or_else(|| {
            governance_error("protected_group_absent", "native group lacks commitments")
        })?;
    serde_json::from_value(commitments)
        .map_err(|_| governance_error("protected_group_shape", "native commitments are malformed"))
}

fn validate_reader_directory(reader_dir: &Path) -> Result<(), TnLlamaError> {
    let metadata = fs::metadata(reader_dir).map_err(|_| {
        governance_error(
            "governance_reader_material_invalid",
            "governance reader directory could not be read",
        )
    })?;
    if !metadata.is_dir() {
        return Err(governance_error(
            "governance_reader_material_invalid",
            "governance reader path is not a directory",
        ));
    }
    let mut entries = fs::read_dir(reader_dir)
        .map_err(|_| {
            governance_error(
                "governance_reader_material_invalid",
                "governance reader directory could not be enumerated",
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            governance_error(
                "governance_reader_material_invalid",
                "governance reader directory could not be enumerated",
            )
        })?;
    if entries.is_empty() {
        return Err(governance_error(
            "governance_reader_material_invalid",
            "reader directory must contain BTN reader kits",
        ));
    }
    let mut has_governance = false;
    for entry in entries.drain(..) {
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if !file_name.ends_with(".btn.mykit")
            || !entry.file_type().is_ok_and(|file_type| file_type.is_file())
        {
            return Err(governance_error(
                "governance_reader_material_invalid",
                "reader directory may contain only BTN reader kits",
            ));
        }
        has_governance |= file_name == "tn.agents.btn.mykit";
    }
    if !has_governance {
        return Err(governance_error(
            "governance_reader_material_invalid",
            "reader directory must contain the tn.agents BTN reader kit",
        ));
    }
    Ok(())
}

fn governance_error(code: &'static str, message: &'static str) -> TnLlamaError {
    TnLlamaError::new(code, AdmissionStage::Governance, message)
}
