use std::collections::VecDeque;

use serde_json::json;

use super::DataObject;
use crate::governed::contracts::base_contract;
use crate::governed::testing::Carry;
use crate::governed::{Governance, GovernedObject};

/// Receive `object`, opening only its `keep` group, and draft its successor.
fn successor_carries(c: &Carry, object: &GovernedObject) -> Vec<GovernedObject> {
    let reader = c.reader();
    let admitted = reader.governance(object).unwrap().authorize("inspect", |_, _| Ok(true)).unwrap();
    let data = DataObject::from_opened(reader.open(&admitted, ["keep"]).unwrap()).unwrap();
    let context = json!({"purpose": "research", "destination": "here"});
    data.draft("data", context).unwrap().carried
}

/// The nearest holder of `group` a reader of the successor finds, breadth first.
fn resolved(carried: &[GovernedObject], group: &str) -> String {
    let mut pending: VecDeque<GovernedObject> = carried.iter().cloned().collect();
    while let Some(holder) = pending.pop_front() {
        if holder.group_names().contains(&group) {
            return holder.id().to_owned();
        }
        pending.extend(holder.carried().iter().cloned());
    }
    panic!("no holder of {group}")
}

fn ids(carried: &[GovernedObject]) -> Vec<&str> {
    carried.iter().map(GovernedObject::id).collect()
}

#[test]
fn a_successor_carries_holders_in_the_order_a_reader_resolves_them() {
    // Group-name order (g, x, z) would put `second` first; breadth-first order puts `first` first.
    let c = Carry::new();
    let (first, second) = (c.seal(&["x", "z"], vec![]), c.seal(&["g", "x"], vec![]));
    let received = c.seal(&["keep"], vec![first.clone(), second.clone()]);
    let carried = successor_carries(&c, &received);
    assert_eq!(resolved(&carried, "x"), first.id(), "receipt resolved x to the first holder");
    assert_eq!(resolved(&carried, "g"), second.id());
}

#[test]
fn a_holder_nested_in_another_carried_holder_travels_once() {
    let c = Carry::new();
    let inner = c.seal(&["g"], vec![]);
    let outer = c.seal(&["x"], vec![inner.clone()]);
    let received = c.seal(&["keep"], vec![outer.clone(), inner.clone()]);
    let carried = successor_carries(&c, &received);
    assert_eq!(ids(&carried), [outer.id()]);
    assert_eq!(resolved(&carried, "g"), inner.id());
}

#[test]
fn a_nested_holder_stays_carried_when_dropping_it_would_reroute_its_group() {
    let c = Carry::new();
    let inner = c.seal(&["g"], vec![]);
    let outer = c.seal(&["x"], vec![inner.clone()]);
    let rival = c.seal(&["g", "y"], vec![]);
    let received = c.seal(&["keep"], vec![outer.clone(), inner.clone(), rival.clone()]);
    let carried = successor_carries(&c, &received);
    assert_eq!(resolved(&carried, "g"), inner.id(), "g keeps the holder receipt chose");
    assert_eq!(resolved(&carried, "y"), rival.id());
    assert_eq!(ids(&carried), [outer.id(), inner.id(), rival.id()]);
}

#[test]
fn additional_machine_rules_are_retained_even_with_the_same_base_contract() {
    let device = crate::DeviceKey::generate();
    let policy=Governance::from_markdown(device.did(),
        "## data\n### instruction\nAnalyze.\n### use_for\nResearch.\n### do_not_use_for\nDisclosure.\n### consequences\nReview.\n### on_violation_or_error\nRefuse.\n",
        "unity/data", "data").unwrap();
    let mut first = policy.clone();
    first.fields.insert("region".into(), json!("eu"));
    let mut second = policy;
    second.fields.insert("region".into(), json!("us"));
    assert!(first.matches_contract(&second));
    let mut data = DataObject::new("data", first, "data", json!({})).unwrap();
    let other = DataObject::new("data", second.clone(), "data", json!({})).unwrap();
    data.include(&other).unwrap();
    data.attach(device.did(), second, |_| Ok(true)).unwrap();
    let policies = data.policies().unwrap();
    assert_eq!(policies.len(), 2);
    assert_eq!(policies[0].get("region"), Some(&json!("eu")));
    assert_eq!(policies[1].get("region"), Some(&json!("us")));
}

fn regional(device: &crate::DeviceKey, region: &str) -> Governance {
    let mut policy=Governance::from_markdown(device.did(),
        "## data\n### instruction\nAnalyze.\n### use_for\nResearch.\n### do_not_use_for\nDisclosure.\n### consequences\nReview.\n### on_violation_or_error\nRefuse.\n",
        "unity/data", "data").unwrap();
    policy.fields.insert("region".into(), json!(region));
    policy
}

#[test]
fn include_all_matches_repeated_include() {
    let device = crate::DeviceKey::generate();
    let object = |region| {
        DataObject::new("data", regional(&device, region), "data", json!({})).unwrap()
    };
    let others = [object("eu"), object("us"), object("eu"), object("ap")];
    let mut repeated = object("base");
    for other in &others {
        repeated.include(other).unwrap();
    }
    let mut bulk = object("base");
    bulk.include_all(others.iter().map(|other| other.inclusion().unwrap()))
        .unwrap();
    assert_eq!(bulk.policies().unwrap(), repeated.policies().unwrap());
    assert_eq!(bulk.policies().unwrap().len(), 4);
    assert_eq!(bulk.sources(), repeated.sources());
}

#[test]
fn base_contract_keeps_the_key_order_of_removal_from_a_full_copy() {
    let device = crate::DeviceKey::generate();
    let mut policy = regional(&device, "eu");
    for name in [
        "dataset_bindings",
        "release_context",
        "source_lineage",
        "attached_policies",
    ] {
        policy.fields.insert(name.into(), json!([name]));
    }
    policy.fields.insert("purpose".into(), json!("research"));
    let mut expected = policy.clone();
    for name in [
        "attached_policies",
        "source_lineage",
        "release_context",
        "dataset_bindings",
    ] {
        expected.fields.remove(name);
    }
    let contract = base_contract(&policy);
    assert!(contract.fields.keys().eq(expected.fields.keys()));
    assert_eq!(contract, expected);
}

#[test]
fn a_path_edit_changes_only_its_group_and_a_failed_edit_changes_nothing() {
    let device = crate::DeviceKey::generate();
    let mut data = DataObject::new_with_groups(
        "data",
        regional(&device, "eu"),
        [("a", json!({"rows": [1, 2], "n": 1})), ("b", json!({"m": 2}))],
    )
    .unwrap();
    data.set_path(&[json!("a"), json!("rows"), json!(1)], json!(5)).unwrap();
    data.append_path(&[json!("a"), json!("rows")], json!(6)).unwrap();
    data.delete_path(&[json!("a"), json!("n")]).unwrap();
    assert_eq!(data.get_path(&[json!("a")]).unwrap(), json!({"rows": [1, 5, 6]}));
    assert_eq!(data.get_path(&[json!("b"), json!("m")]).unwrap(), json!(2));
    let before = (data.groups().clone(), data.revision());
    assert!(data.set_path(&[json!("a"), json!("rows"), json!(9)], json!(0)).is_err());
    assert!(data.append_path(&[json!("a")], json!(0)).is_err());
    assert!(data.delete_path(&[json!("b"), json!("absent")]).is_err());
    assert!(data.set_path(&[json!("missing"), json!("x")], json!(0)).is_err());
    assert_eq!((data.groups().clone(), data.revision()), before);
}

#[test]
fn list_path_operations_follow_python_list_semantics_and_fail_atomically() {
    let device = crate::DeviceKey::generate();
    let rows = || json!({"rows": [0, 1, 2, 3, 4]});
    let mut data = DataObject::new("data", regional(&device, "eu"), "a", rows()).unwrap();
    let path = [json!("a"), json!("rows")];
    data.insert_path(&path, -1, json!(9)).unwrap();
    data.insert_path(&path, 99, json!(8)).unwrap();
    assert_eq!(data.get_path(&path).unwrap(), json!([0, 1, 2, 3, 9, 4, 8]));
    data.slice_path(&path, Some(1), Some(-1), 2, vec![json!("x"), json!("y"), json!("z")], false).unwrap();
    assert_eq!(data.get_path(&path).unwrap(), json!([0, "x", 2, "y", 9, "z", 8]));
    data.slice_path(&path, None, None, -3, Vec::new(), true).unwrap();
    assert_eq!(data.get_path(&path).unwrap(), json!(["x", 2, 9, "z"]));
    data.slice_path(&path, Some(1), Some(3), 1, vec![json!(7)], false).unwrap();
    data.extend_path(&path, vec![json!(5), json!(6)]).unwrap();
    data.reverse_path(&path).unwrap();
    assert_eq!(data.get_path(&path).unwrap(), json!([6, 5, "z", 7, "x"]));
    assert_eq!(data.take_path(&[json!("a"), json!("rows"), json!(0)]).unwrap(), json!(6));
    let before = (data.groups().clone(), data.revision());
    assert!(data.slice_path(&path, None, None, 0, Vec::new(), true).is_err(), "zero step");
    assert!(data.slice_path(&path, None, None, 2, vec![json!(1)], false).is_err(), "length mismatch");
    assert!(data.insert_path(&[json!("a")], 0, json!(1)).is_err(), "a group is not a list");
    assert!(data.reverse_path(&[]).is_err());
    assert_eq!((data.groups().clone(), data.revision()), before);
}
