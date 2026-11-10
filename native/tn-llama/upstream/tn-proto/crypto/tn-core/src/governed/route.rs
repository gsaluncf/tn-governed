//! Routed receipt: a group the received object carries in a whole input object
//! opens from its nearest holder, after every object on the path accepts it.
//!
//! A route starts at the received object. For each requested group it follows
//! the carried objects breadth first to the nearest holder. Every object on a
//! group's path accepts that group, and the holder alone supplies it.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    invalid, AdmittedObject, DatasetSelection, Governance, GovernedObject, OpenedObject,
    GOVERNANCE_GROUP,
};
use crate::Result;

/// One object a strict receipt admits: the groups whose path runs through it,
/// and the groups it holds and supplies itself.
pub(super) struct Stop {
    pub(super) object: GovernedObject,
    pub(super) accepted: Vec<String>,
    pub(super) supplied: Vec<String>,
}

/// The objects a strict receipt admits, the received object first.
pub(super) struct Route {
    pub(super) stops: Vec<Stop>,
}

impl Route {
    pub(super) fn resolve<I, S>(direct: &GovernedObject, groups: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let requested = requested_groups(groups)?;
        let mut nodes: Vec<(GovernedObject, Option<usize>)> = vec![(direct.clone(), None)];
        let mut holder_of = BTreeMap::new();
        let mut next = 0;
        while next < nodes.len() && holder_of.len() < requested.len() {
            for group in &requested {
                if !holder_of.contains_key(group) && nodes[next].0.groups.contains_key(group) {
                    holder_of.insert(group.clone(), next);
                }
            }
            let carried = nodes[next].0.carried().to_vec();
            nodes.extend(carried.into_iter().map(|object| (object, Some(next))));
            next += 1;
        }
        if let Some(missing) = requested.iter().find(|group| !holder_of.contains_key(*group)) {
            return Err(invalid(format!("select each present business group once: {missing:?}")));
        }
        Ok(Self::along_paths(&nodes, &holder_of))
    }

    /// Mark every object on each group's path, keyed by breadth-first position.
    fn along_paths(
        nodes: &[(GovernedObject, Option<usize>)],
        holder_of: &BTreeMap<String, usize>,
    ) -> Self {
        let mut stops: BTreeMap<usize, Stop> = BTreeMap::new();
        for (group, &holder) in holder_of {
            let mut at = Some(holder);
            while let Some(index) = at {
                let stop = stops.entry(index).or_insert_with(|| Stop {
                    object: nodes[index].0.clone(),
                    accepted: Vec::new(),
                    supplied: Vec::new(),
                });
                stop.accepted.push(group.clone());
                if index == holder {
                    stop.supplied.push(group.clone());
                }
                at = nodes[index].1;
            }
        }
        Self { stops: stops.into_values().collect() }
    }

    /// Each selection, keyed by the object it pins, which must supply a requested group.
    pub(super) fn selections<'s>(
        &self,
        given: impl IntoIterator<Item = &'s DatasetSelection>,
    ) -> Result<BTreeMap<String, &'s DatasetSelection>> {
        let mut selections = BTreeMap::new();
        for selection in given {
            let id = selection.source_object_id();
            if !self.stops.iter().any(|stop| stop.object.id() == id && !stop.supplied.is_empty()) {
                return Err(invalid(
                    "received publication must match the selected source identity, writer and type",
                ));
            }
            if selections.insert(id.to_owned(), selection).is_some() {
                return Err(invalid("select at most one dataset edition per source object"));
            }
        }
        Ok(selections)
    }
}

/// Requested group names: at least one, each once, never the governance group.
fn requested_groups<I, S>(groups: I) -> Result<Vec<String>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut requested = BTreeSet::new();
    for name in groups {
        let name = name.as_ref();
        if name == GOVERNANCE_GROUP || !requested.insert(name.to_owned()) {
            return Err(invalid(format!("select each present business group once: {name:?}")));
        }
    }
    if requested.is_empty() {
        return Err(invalid("strict admission requires at least one business group"));
    }
    Ok(requested.into_iter().collect())
}

/// A strict receipt every object on its route accepted, not yet opened. Open a
/// supplier's groups with its admission, then assemble them through the same
/// reader; the received object stays the working copy's source.
pub struct AdmittedRoute {
    stops: Vec<Stop>,
    admitted: Vec<AdmittedObject>,
    selections: Vec<DatasetSelection>,
}

impl AdmittedRoute {
    pub(super) fn new(route: Route, admitted: Vec<AdmittedObject>, selections: Vec<DatasetSelection>) -> Self {
        Self { stops: route.stops, admitted, selections }
    }

    /// The policies the received working copy holds: the received object's, with
    /// those of every holder and path object included.
    pub fn policies(&self) -> Result<Vec<Governance>> {
        let (direct, others) = self.admitted.split_first().expect("a route starts at its source");
        super::contracts::included_policies(direct.governance(), others.iter().map(AdmittedObject::governance))
    }

    /// The admission of the object that supplies `group`.
    pub fn supplier(&self, group: &str) -> Option<&AdmittedObject> {
        self.position_of(group).map(|index| &self.admitted[index])
    }

    /// Each admitted object on the route with the groups it supplies, the received object first.
    pub fn stops(&self) -> impl Iterator<Item = (&AdmittedObject, &[String])> {
        self.admitted.iter().zip(&self.stops).map(|(admitted, stop)| (admitted, stop.supplied.as_slice()))
    }

    /// The verified selections to bind once the working copy is assembled.
    pub(super) fn selections(&self) -> &[DatasetSelection] {
        &self.selections
    }

    fn position_of(&self, group: &str) -> Option<usize> {
        self.stops.iter().position(|stop| stop.supplied.iter().any(|name| name == group))
    }

    /// The route position `opened` belongs to: the same object, opened under this
    /// route's own admission, holding only groups that object supplies.
    pub(super) fn position(&self, opened: &OpenedObject) -> Result<usize> {
        let index = self
            .admitted
            .iter()
            .position(|admitted| admitted.same_admission(opened.admitted()))
            .ok_or_else(|| invalid("opened groups do not belong to this admitted route"))?;
        let supplied = &self.stops[index].supplied;
        if opened.groups().keys().any(|name| !supplied.contains(name)) {
            return Err(invalid("an object on a route opens only the groups it supplies"));
        }
        Ok(index)
    }
}
