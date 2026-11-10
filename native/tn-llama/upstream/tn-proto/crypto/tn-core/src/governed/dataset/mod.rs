//! Signed edition records and explicit, application-approved dataset selection.
//!
//! [`bindings`] holds the portable declarations a working copy carries, [`artifacts`]
//! the evaluator digests, [`edition`] the signed records, [`catalog`] the accepted
//! state, and [`selection`] receipt checked against it.
mod artifacts;
mod bindings;
mod catalog;
mod edition;
mod selection;

pub use artifacts::EvaluatorArtifactSet;
pub(super) use bindings::merge_bindings;
pub use bindings::{ContractBinding, DatasetBinding};
pub use catalog::{DatasetCatalog, PreparedEdition};
pub use edition::{DatasetEdition, DatasetEditionDraft};
pub use selection::DatasetSelection;

use super::validate_name;
use crate::{Error, Result};

/// Ordinary TN object type used for signed dataset edition records.
pub const DATASET_EDITION_TYPE: &str = "tn.dataset.edition";
/// Encrypted group containing the edition record.
pub const DATASET_EDITION_GROUP: &str = "dataset_edition";
const EDITION_SCHEMA: &str = "tn-dataset-edition@v1";
const MAX_ITEMS: usize = 256;
const MAX_CONTRACTS: usize = 64;
const MAX_USES: usize = 1024;
const MAX_LABEL_BYTES: usize = 256;
const MAX_GRANT_BYTES: usize = 2048;
const MAX_BINDINGS: usize = 1024;

fn invalid(reason: impl Into<String>) -> Error {
    Error::Malformed {
        kind: "dataset edition",
        reason: reason.into(),
    }
}

fn label(value: &str) -> Result<()> {
    if value.len() > MAX_LABEL_BYTES {
        return Err(invalid(
            "dataset, edition, scope, type and group labels are bounded to 256 bytes",
        ));
    }
    validate_name(value)
}

fn bounded_nonempty<T>(items: &[T], max: usize, name: &str) -> Result<()> {
    if items.is_empty() || items.len() > max {
        return Err(invalid(format!(
            "{name} requires between 1 and {max} entries"
        )));
    }
    Ok(())
}
