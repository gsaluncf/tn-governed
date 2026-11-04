//! Digests of the external evaluator that checks one policy revision.
use serde::{Deserialize, Deserializer, Serialize};

use super::invalid;
use crate::governed::revision::validate_revision_id;
use crate::Result;

/// Digests binding one policy revision to the evaluator's complete artifact set.
/// Digests use exactly 64 lowercase hexadecimal characters, without a prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvaluatorArtifactSet {
    policy_revision: String,
    compiled_policy_sha256: String,
    profile_sha256: String,
    wasm_sha256: String,
    data_sha256: String,
}

impl EvaluatorArtifactSet {
    /// Validate the revision identity and all four artifact digests.
    pub fn new(
        policy_revision: &str,
        compiled_policy_sha256: &str,
        profile_sha256: &str,
        wasm_sha256: &str,
        data_sha256: &str,
    ) -> Result<Self> {
        validate_revision_id(policy_revision)?;
        for digest in [
            compiled_policy_sha256,
            profile_sha256,
            wasm_sha256,
            data_sha256,
        ] {
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(invalid(
                    "artifact digests require 64 lowercase hexadecimal characters",
                ));
            }
        }
        Ok(Self {
            policy_revision: policy_revision.to_owned(),
            compiled_policy_sha256: compiled_policy_sha256.to_owned(),
            profile_sha256: profile_sha256.to_owned(),
            wasm_sha256: wasm_sha256.to_owned(),
            data_sha256: data_sha256.to_owned(),
        })
    }
    /// Policy revision evaluated by these artifacts.
    pub fn policy_revision(&self) -> &str {
        &self.policy_revision
    }
    /// Digest of the compiled policy source or representation.
    pub fn compiled_policy_sha256(&self) -> &str {
        &self.compiled_policy_sha256
    }
    /// Digest of the evaluator's schema/profile.
    pub fn profile_sha256(&self) -> &str {
        &self.profile_sha256
    }
    /// Digest of the exact executable evaluator module.
    pub fn wasm_sha256(&self) -> &str {
        &self.wasm_sha256
    }
    /// Digest of the evaluator's accompanying data.
    pub fn data_sha256(&self) -> &str {
        &self.data_sha256
    }
}

impl<'de> Deserialize<'de> for EvaluatorArtifactSet {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            policy_revision: String,
            compiled_policy_sha256: String,
            profile_sha256: String,
            wasm_sha256: String,
            data_sha256: String,
        }
        let fields = Fields::deserialize(deserializer)?;
        Self::new(
            &fields.policy_revision,
            &fields.compiled_policy_sha256,
            &fields.profile_sha256,
            &fields.wasm_sha256,
            &fields.data_sha256,
        )
        .map_err(serde::de::Error::custom)
    }
}
