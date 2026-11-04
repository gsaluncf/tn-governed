use super::*;
use crate::governed::testing::{usage, Carry};

fn asked_by(c: &Carry, object: &GovernedObject, groups: &[&str]) -> Vec<(String, Vec<String>)> {
    let mut asked = Vec::new();
    c.reader()
        .receive_for(object, &usage(), groups, None, |ctx| {
            asked.push((ctx.object().id().to_owned(), ctx.groups().unwrap().to_vec()));
            Ok(true)
        })
        .unwrap();
    asked
}

fn named(object: &GovernedObject, groups: &[&str]) -> (String, Vec<String>) {
    (object.id().to_owned(), groups.iter().map(|g| (*g).to_owned()).collect())
}

#[test]
fn strict_receipt_opens_a_group_its_direct_input_carries() {
    let c = Carry::new();
    let holder = c.seal(&["x"], vec![]);
    let direct = c.seal(&["keep"], vec![holder.clone()]);
    let data = c.reader().receive_for(&direct, &usage(), ["x"], None, |_| Ok(true)).unwrap();
    assert_eq!(data.group("x").unwrap()["from"], "x");
    assert_eq!(data.sources()[0].object_id(), direct.id(), "the direct input stays the source");
}

#[test]
fn routed_receipt_asks_the_direct_input_and_the_holder_for_the_group() {
    let c = Carry::new();
    let holder = c.seal(&["x"], vec![]);
    let direct = c.seal(&["keep"], vec![holder.clone()]);
    let asked = asked_by(&c, &direct, &["keep", "x"]);
    assert_eq!(asked, [named(&direct, &["keep", "x"]), named(&holder, &["x"])]);
}

#[test]
fn a_nested_route_asks_every_object_on_it() {
    let c = Carry::new();
    let holder = c.seal(&["x"], vec![]);
    let middle = c.seal(&["y"], vec![holder.clone()]);
    let direct = c.seal(&["keep"], vec![middle.clone()]);
    let asked = asked_by(&c, &direct, &["x"]);
    assert_eq!(asked, [named(&direct, &["x"]), named(&middle, &["x"]), named(&holder, &["x"])]);
}

#[test]
fn either_refusal_keeps_a_carried_group_closed() {
    let c = Carry::new();
    let holder = c.seal(&["x"], vec![]);
    let direct = c.seal(&["keep"], vec![holder.clone()]);
    for refused in [direct.id(), holder.id()] {
        let result = c.reader().receive_for(&direct, &usage(), ["x"], None, |ctx| {
            Ok(ctx.object().id() != refused)
        });
        assert!(result.is_err(), "refusal by {refused}");
    }
}

#[test]
fn admission_alone_asks_the_same_objects_and_needs_no_group_key() {
    let c = Carry::new();
    let holder = c.seal(&["x"], vec![]);
    let direct = c.seal(&["keep"], vec![holder.clone()]);
    let mut asked = Vec::new();
    c.reader_without(Some("x"))
        .admit_for(&direct, &usage(), ["x"], None, |ctx| {
            asked.push((ctx.object().id().to_owned(), ctx.groups().unwrap().to_vec()));
            Ok(true)
        })
        .unwrap();
    assert_eq!(asked, [named(&direct, &["x"]), named(&holder, &["x"])]);
}

#[test]
fn admission_returns_the_policies_the_received_copy_holds() {
    let c = Carry::new();
    let holder = c.seal(&["x"], vec![]);
    let direct = c.seal(&["keep"], vec![holder.clone()]);
    let reader = c.reader();
    let policies = reader.admit_for(&direct, &usage(), ["x"], None, |_| Ok(true)).unwrap();
    let data = reader.receive_for(&direct, &usage(), ["x"], None, |_| Ok(true)).unwrap();
    assert_eq!(policies, data.policies().unwrap());
    assert_eq!(policies.len(), 1, "a holder under the same contract adds nothing");
}

fn key_of(reader: &GovernedReader, object: &GovernedObject) -> String {
    reader.governance_hash_key(&reader.governance(object).unwrap()).unwrap()
}

#[test]
fn a_carried_group_opens_with_its_holders_key_and_assembles_under_the_source() {
    let c = Carry::new();
    let holder = c.seal(&["x"], vec![]);
    let direct = c.seal(&["keep"], vec![holder.clone()]);
    let reader = c.reader();
    let route = reader.admit_route(&direct, &usage(), ["x"], None, |_| Ok(true)).unwrap();
    let supplier = route.supplier("x").unwrap();
    assert_eq!(supplier.object().id(), holder.id());
    assert!(reader.open_with_hash_key(supplier, ["x"], &key_of(&reader, &direct)).is_err(),
        "the source's key does not name the holder's governance");
    let opened = reader.open_with_hash_key(supplier, ["x"], &key_of(&reader, &holder)).unwrap();
    let data = reader.assemble(&route, vec![opened]).unwrap();
    assert_eq!(data.group("x").unwrap()["from"], "x");
    assert_eq!(data.sources()[0].object_id(), direct.id());
}

#[test]
fn a_part_opened_under_another_admission_does_not_assemble() {
    let c = Carry::new();
    let holder = c.seal(&["x"], vec![]);
    let direct = c.seal(&["keep"], vec![holder.clone()]);
    let reader = c.reader();
    let route = reader.admit_route(&direct, &usage(), ["x"], None, |_| Ok(true)).unwrap();
    let other = reader.admit_route(&direct, &usage(), ["x"], None, |_| Ok(true)).unwrap();
    let foreign = reader.open(other.supplier("x").unwrap(), ["x"]).unwrap();
    assert!(reader.assemble(&route, vec![foreign]).is_ok(), "same reader, use, and groups is the same admission");
    let elsewhere = c.reader();
    let stranger = elsewhere.admit_route(&direct, &usage(), ["x"], None, |_| Ok(true)).unwrap();
    let foreign = elsewhere.open(stranger.supplier("x").unwrap(), ["x"]).unwrap();
    assert!(reader.assemble(&route, vec![foreign]).is_err(), "another reader context is refused");
}

#[test]
fn the_route_supplier_is_the_objects_own_nearest_holder() {
    let c = Carry::new();
    let inner = c.seal(&["x", "g"], vec![]);
    let outer = c.seal(&["y"], vec![inner.clone()]);
    let rival = c.seal(&["x"], vec![]);
    let direct = c.seal(&["keep"], vec![outer.clone(), rival.clone()]);
    let route = c.reader().admit_route(&direct, &usage(), ["x", "g", "y"], None, |_| Ok(true)).unwrap();
    for group in ["x", "g", "y"] {
        assert_eq!(route.supplier(group).unwrap().object().id(), direct.holder(group).unwrap().id(), "{group}");
    }
    assert_eq!(direct.holder("x").unwrap().id(), rival.id(), "breadth first: the rival is nearer than inner");
}

#[test]
fn a_group_no_object_on_the_route_holds_is_refused_before_any_decision() {
    let c = Carry::new();
    let direct = c.seal(&["keep"], vec![c.seal(&["x"], vec![])]);
    let result = c.reader().receive_for(&direct, &usage(), ["y"], None, |_| -> Result<bool> {
        panic!("no decision before the route is known")
    });
    assert!(result.is_err());
}

#[test]
fn an_index_key_reader_opens_values_that_match_their_field_hashes() {
    let c = Carry::new();
    let object = c.seal(&["x"], vec![]);
    let data = c.reader().receive_for(&object, &usage(), ["x"], None, |_| Ok(true)).unwrap();
    assert_eq!(data.group("x").unwrap()["from"], "x");
}

#[test]
fn an_index_key_reader_refuses_values_that_differ_from_their_field_hashes() {
    let c = Carry::new();
    let object = c.seal(&["x"], vec![]);
    // The writer hashed every field under [1; 32]; this reader recomputes under another key.
    let reader = c.names_only_reader().with_group_index_key("x", &[2; 32]).unwrap();
    let error = reader.receive_for(&object, &usage(), ["x"], None, |_| Ok(true)).err().unwrap();
    assert!(error.to_string().contains("signed field hash"), "{error}");
}

#[test]
fn a_reader_without_a_groups_index_key_opens_it_by_field_names() {
    let c = Carry::new();
    let object = c.seal(&["x"], vec![]);
    let reader = c.names_only_reader();
    let data = reader.receive_for(&object, &usage(), ["x"], None, |_| Ok(true)).unwrap();
    assert_eq!(data.group("x").unwrap()["from"], "x");
}

#[test]
fn a_reader_holds_one_index_key_per_group() {
    let reader = GovernedReader::new().with_group_index_key("x", &[1; 32]).unwrap();
    assert!(reader.with_group_index_key("x", &[1; 32]).is_err());
    let reader = GovernedReader::new().with_governance_index_key(&[1; 32]).unwrap();
    assert!(reader.with_group_index_key(GOVERNANCE_GROUP, &[2; 32]).is_err());
}

#[test]
fn a_prepared_admission_opens_after_the_same_objects_confirm_it() {
    let c = Carry::new();
    let holder = c.seal(&["x"], vec![]);
    let direct = c.seal(&["keep"], vec![holder.clone()]);
    let reader = c.reader();
    let route = reader.admit_route(&direct, &usage(), ["keep", "x"], None, |_| Ok(true)).unwrap();
    let mut asked = Vec::new();
    let data = reader
        .receive_admitted(&route, |ctx| {
            asked.push((ctx.object().id().to_owned(), ctx.groups().unwrap().to_vec()));
            Ok(true)
        })
        .unwrap();
    assert_eq!(asked, [named(&direct, &["keep", "x"]), named(&holder, &["x"])]);
    assert_eq!(data.group("x").unwrap()["from"], "x");
    assert_eq!(data.sources()[0].object_id(), direct.id(), "the direct input stays the source");
}

#[test]
fn a_prepared_admission_refused_on_confirmation_opens_nothing() {
    let c = Carry::new();
    let holder = c.seal(&["x"], vec![]);
    let direct = c.seal(&["keep"], vec![holder.clone()]);
    let reader = c.reader();
    let route = reader.admit_route(&direct, &usage(), ["x"], None, |_| Ok(true)).unwrap();
    let refused = reader.receive_admitted(&route, |ctx| Ok(ctx.object().id() != holder.id()));
    assert!(matches!(refused, Err(Error::UseDenied { .. })));
}

#[test]
fn a_prepared_admission_opens_only_under_the_reader_that_made_it() {
    let c = Carry::new();
    let direct = c.seal(&["x"], vec![]);
    let route = c.reader().admit_route(&direct, &usage(), ["x"], None, |_| Ok(true)).unwrap();
    assert!(c.reader().receive_admitted(&route, |_| Ok(true)).is_err());
}
