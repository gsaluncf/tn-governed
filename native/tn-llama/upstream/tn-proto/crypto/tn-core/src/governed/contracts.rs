//! Contract normalization and the one merge of policy sets.
use super::{invalid, Governance};
use crate::Result;
use serde_json::{json, Map, Value};

/// A contract without the carried lists every successor rewrites.
pub(super) fn base_contract(policy: &Governance) -> Governance {
    const CARRIED: [&str; 4] = [
        "attached_policies",
        "source_lineage",
        "release_context",
        "dataset_bindings",
    ];
    // Carried lists can be long. Leave them behind before removing their keys.
    let mut fields = Map::new();
    for (name, value) in &policy.fields {
        let kept = !CARRIED.contains(&name.as_str());
        fields.insert(name.clone(), if kept { value.clone() } else { Value::Null });
    }
    for name in CARRIED {
        fields.remove(name);
    }
    Governance::with_fields(policy, fields)
}

/// Append each of `additional`'s contracts to `target`'s attached policies, in order,
/// skipping any `target` already holds. The current set is decoded once.
pub(super) fn merge_policies(
    target: &mut Governance,
    additional: impl IntoIterator<Item = Governance>,
) -> Result<()> {
    let mut policies = target.policies()?;
    for policy in additional {
        let policy = base_contract(&policy);
        if policies.contains(&policy) {
            continue;
        }
        if policies.len() >= 64 {
            return Err(invalid("object supports at most 64 attached contracts"));
        }
        let record = json!({"governed_by": policy.governed_by(), "fields": policy.fields()});
        target
            .fields
            .entry("attached_policies")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or_else(|| invalid("attached policies require an array"))?
            .push(record);
        policies.push(policy);
    }
    Ok(())
}

/// The policies a working copy holds once `others` are included into `primary`:
/// the merge a working copy's inclusion performs, without a working copy.
pub(crate) fn included_policies<'g>(
    primary: &Governance,
    others: impl IntoIterator<Item = &'g Governance>,
) -> Result<Vec<Governance>> {
    let mut additional = Vec::new();
    for other in others {
        additional.extend(other.policies()?);
    }
    let mut candidate = primary.clone();
    merge_policies(&mut candidate, additional)?;
    candidate.policies()
}

impl Governance {
    /// Primary and appended contracts, each retaining its own authority and revision.
    pub fn policies(&self) -> Result<Vec<Governance>> {
        let mut policies = vec![base_contract(self)];
        if let Some(value) = self.get("attached_policies") {
            let values = value
                .as_array()
                .ok_or_else(|| invalid("attached policies require an array"))?;
            if values.len() >= 64 {
                return Err(invalid("object supports at most 64 attached contracts"));
            }
            for value in values {
                let record = value
                    .as_object()
                    .filter(|record| record.len() == 2)
                    .ok_or_else(|| invalid("attached policy requires authority and fields"))?;
                let authority = record
                    .get("governed_by")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("attached policy requires authority"))?;
                let fields = record
                    .get("fields")
                    .and_then(Value::as_object)
                    .ok_or_else(|| invalid("attached policy requires fields"))?;
                if fields.contains_key("attached_policies") {
                    return Err(invalid("attached policy list must be flat"));
                }
                let policy = Governance::from_body(authority, fields.clone())?;
                if policies.contains(&policy) {
                    return Err(invalid("attached policies must be distinct"));
                }
                policies.push(policy);
            }
        }
        Ok(policies)
    }
}
