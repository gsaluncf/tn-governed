//! The whole objects a working copy carries for the groups it never opened.
use super::{GovernedObject, GOVERNANCE_GROUP};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, VecDeque};

/// Each unopened business group of `object` and of the whole objects it carries,
/// paired with the nearest object holding it, and those holders in the
/// breadth-first order that resolved them. Groups the reader opened shadow them.
pub(super) fn unopened_groups(
    object: &GovernedObject,
    opened: &BTreeMap<String, Map<String, Value>>,
) -> (BTreeMap<String, GovernedObject>, Vec<GovernedObject>) {
    let mut opaque = BTreeMap::new();
    let mut holders = Vec::new();
    let mut pending = VecDeque::from([object.clone()]);
    while let Some(holder) = pending.pop_front() {
        let mut selected = false;
        for name in holder.group_names() {
            if name != GOVERNANCE_GROUP && !opened.contains_key(name) && !opaque.contains_key(name) {
                opaque.insert(name.to_owned(), holder.clone());
                selected = true;
            }
        }
        if selected {
            holders.push(holder.clone());
        }
        pending.extend(holder.carried().iter().cloned());
    }
    (opaque, holders)
}

/// The whole objects a release carries: the holders of the remaining unopened
/// groups in resolution order. A holder that another carried holder already
/// contains is dropped, unless a reader would then find a different holder.
pub(super) fn carried_holders(
    opaque: &BTreeMap<String, GovernedObject>,
    holders: &[GovernedObject],
) -> Vec<GovernedObject> {
    let target: BTreeMap<&str, &str> = opaque.iter().map(|(g, h)| (g.as_str(), h.id())).collect();
    let mut carried: Vec<GovernedObject> = holders
        .iter()
        .filter(|holder| target.values().any(|id| *id == holder.id()))
        .cloned()
        .collect();
    for index in (0..carried.len()).rev() {
        let mut trial = carried.clone();
        trial.remove(index);
        if resolves_to(&trial, &target) {
            carried = trial;
        }
    }
    carried
}

/// Whether a breadth-first walk over `carried` finds `target`'s holder for every group.
fn resolves_to(carried: &[GovernedObject], target: &BTreeMap<&str, &str>) -> bool {
    let mut found: BTreeMap<&str, String> = BTreeMap::new();
    let mut pending: VecDeque<GovernedObject> = carried.iter().cloned().collect();
    while let Some(holder) = pending.pop_front() {
        for name in holder.group_names() {
            if let Some((group, _)) = target.get_key_value(name) {
                found.entry(group).or_insert_with(|| holder.id().to_owned());
            }
        }
        pending.extend(holder.carried().iter().cloned());
    }
    target.iter().all(|(group, id)| found.get(group).map(String::as_str) == Some(*id))
}
