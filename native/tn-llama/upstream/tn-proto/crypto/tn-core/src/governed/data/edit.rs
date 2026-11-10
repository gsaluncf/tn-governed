//! Plaintext edits and projections of a working copy. A path edit copies and
//! validates only the group it names, and a failed edit changes nothing.
use super::DataObject;
use crate::governed::{invalid, validate_field, validate_group, GOVERNANCE_GROUP};
use crate::Result;
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

impl DataObject {
    /// Read a business field, or the complete opened group when field is None.
    pub fn get(&self, group: &str, field: Option<&str>) -> Result<Value> {
        business_group(group)?;
        let fields = self
            .groups
            .get(group)
            .ok_or_else(|| invalid(format!("no opened group {group:?}")))?;
        match field {
            Some(name) => fields
                .get(name)
                .cloned()
                .ok_or_else(|| invalid(format!("no field {name:?} in {group:?}"))),
            None => Ok(Value::Object(fields.clone())),
        }
    }
    /// Change a business field or replace a group; contracts remain attached.
    pub fn set(&mut self, group: &str, field: Option<&str>, value: Value) -> Result<()> {
        match field {
            Some(name) => self.set_field(group, name, value),
            None => self.set_group(group, value),
        }
    }
    /// Select retained groups and optionally fields within opened groups, atomically.
    /// A field projection must name a retained, opened group and existing fields.
    pub fn select<I, S>(
        &mut self,
        groups: I,
        fields: Option<&BTreeMap<String, Vec<String>>>,
    ) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut candidate = self.clone();
        candidate.retain_groups(groups)?;
        if let Some(projections) = fields {
            for (group, names) in projections {
                business_group(group)?;
                let original = candidate.groups.get(group).ok_or_else(|| {
                    invalid(format!(
                        "field selection requires retained opened group {group:?}"
                    ))
                })?;
                let mut selected = Map::new();
                for name in names {
                    let value = original
                        .get(name)
                        .ok_or_else(|| invalid(format!("no field {name:?} in {group:?}")))?;
                    if selected.insert(name.clone(), value.clone()).is_some() {
                        return Err(invalid(format!("duplicate selected field {name:?}")));
                    }
                }
                candidate.set_group(group, selected)?;
            }
        }
        *self = candidate;
        Ok(())
    }
    /// Set a complete plaintext group. Governance names are reserved.
    pub fn set_group(&mut self, name: &str, fields: impl Serialize) -> Result<()> {
        business_group(name)?;
        let Value::Object(fields) = serde_json::to_value(fields)? else {
            return Err(invalid("group fields must be a JSON object"));
        };
        for field in fields.keys() {
            validate_field(field)?;
        }
        self.groups.insert(name.to_owned(), fields);
        self.opaque.remove(name);
        self.changed();
        Ok(())
    }
    /// Update one field in an opened group.
    pub fn set_field(&mut self, group: &str, field: &str, value: Value) -> Result<()> {
        self.set_path(&[Value::from(group), Value::from(field)], value)
    }
    /// Name the opened business group every data group of the next release is bound to.
    pub fn set_manifest(&mut self, name: &str) -> Result<()> {
        business_group(name)?;
        if !self.groups.contains_key(name) {
            return Err(invalid(format!("manifest {name:?} must be an opened business group")));
        }
        if self.manifest.as_deref() != Some(name) {
            self.manifest = Some(name.to_owned());
            self.changed();
        }
        Ok(())
    }
    /// Remove a business group from the next version; prior snapshots remain intact.
    pub fn remove_group(&mut self, name: &str) -> Result<()> {
        business_group(name)?;
        if self.groups.remove(name).is_none() && self.opaque.remove(name).is_none() {
            return Err(invalid(format!("no group {name:?}")));
        }
        self.drop_removed_manifest();
        self.changed();
        Ok(())
    }
    /// A removed manifest group leaves the next release without a manifest.
    fn drop_removed_manifest(&mut self) {
        if self.manifest.as_ref().is_some_and(|name| !self.groups.contains_key(name)) {
            self.manifest = None;
        }
    }
    /// Keep only the named business groups in the next output, including any
    /// explicitly selected opaque groups. Policies and signed history remain.
    /// Every name must exist; all validation precedes any mutation. An empty
    /// selection removes every business group. Repeating a name is harmless.
    pub fn retain_groups<I, S>(&mut self, names: I) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut selected = BTreeSet::new();
        for name in names {
            let name = name.as_ref();
            business_group(name)?;
            if !self.groups.contains_key(name) && !self.opaque.contains_key(name) {
                return Err(invalid(format!("no group {name:?}")));
            }
            selected.insert(name.to_owned());
        }
        let before = self.groups.len() + self.opaque.len();
        self.groups.retain(|name, _| selected.contains(name));
        self.opaque.retain(|name, _| selected.contains(name));
        if before != self.groups.len() + self.opaque.len() {
            self.drop_removed_manifest();
            self.changed();
        }
        Ok(())
    }
    /// Copy a selected JSON value. Path elements are dictionary keys or list indices;
    /// the first names an opened group, and an empty path copies every opened group.
    pub fn get_path(&self, path: &[Value]) -> Result<Value> {
        let Some((group, inner)) = path.split_first() else {
            let groups = self.groups.iter();
            return Ok(Value::Object(
                groups.map(|(name, fields)| (name.clone(), Value::Object(fields.clone()))).collect(),
            ));
        };
        let fields = self.opened(group)?;
        let Some((field, inner)) = inner.split_first() else {
            return Ok(Value::Object(fields.clone()));
        };
        let mut node = field
            .as_str()
            .and_then(|name| fields.get(name))
            .ok_or_else(|| invalid("data path not found"))?;
        for key in inner {
            node = child(node, key)?;
        }
        Ok(node.clone())
    }
    /// Atomically replace a nested value, retaining policies and unopened groups.
    /// A one-element path replaces or creates a whole group.
    pub fn set_path(&mut self, path: &[Value], value: Value) -> Result<()> {
        let Some((last, parents)) = path.split_last() else {
            return Err(invalid("assign a group or a field"));
        };
        let Some((group, inner)) = parents.split_first() else {
            let name = last.as_str().ok_or_else(not_a_key_or_index)?;
            return self.set_group(name, value);
        };
        self.edit_group(group, |root| assign(descend(root, inner)?, last, value))
    }
    /// Atomically append to a selected nested list.
    pub fn append_path(&mut self, path: &[Value], value: Value) -> Result<()> {
        let Some((group, inner)) = path.split_first() else {
            return Err(invalid("append requires a list"));
        };
        self.edit_group(group, |root| {
            descend(root, inner)?
                .as_array_mut()
                .ok_or_else(|| invalid("append requires a list"))?
                .push(value);
            Ok(())
        })
    }
    /// Atomically delete a selected dictionary field or list item.
    pub fn delete_path(&mut self, path: &[Value]) -> Result<()> {
        if path.len() == 1 {
            let name = path[0].as_str().ok_or_else(|| invalid("group requires a string"))?;
            return self.remove_group(name);
        }
        let (last, parents) = path
            .split_last()
            .ok_or_else(|| invalid("delete requires a path"))?;
        let (group, inner) = parents.split_first().expect("two or more path elements");
        self.edit_group(group, |root| match (descend(root, inner)?, last) {
            (Value::Object(map), Value::String(name)) => {
                map.remove(name).map(drop).ok_or_else(|| invalid("field not found"))
            }
            (Value::Array(items), Value::Number(index)) => {
                let i = list_index(index)
                    .filter(|i| *i < items.len())
                    .ok_or_else(|| invalid("list index out of range"))?;
                items.remove(i);
                Ok(())
            }
            _ => Err(invalid("invalid deletion path")),
        })
    }
    /// Atomically insert into a selected nested list, as Python's `insert` does: a
    /// negative index counts from the end, and an index past either end clamps to it.
    pub fn insert_path(&mut self, path: &[Value], index: isize, value: Value) -> Result<()> {
        self.edit_list(path, "insert", |items| {
            let length = items.len() as isize;
            let index = if index < 0 { (length + index).max(0) } else { index.min(length) };
            items.insert(index as usize, value);
            Ok(())
        })
    }
    /// Atomically reverse a selected nested list.
    pub fn reverse_path(&mut self, path: &[Value]) -> Result<()> {
        self.edit_list(path, "reverse", |items| {
            items.reverse();
            Ok(())
        })
    }
    /// Atomically extend a selected nested list.
    pub fn extend_path(&mut self, path: &[Value], values: Vec<Value>) -> Result<()> {
        self.edit_list(path, "extend", |items| {
            items.extend(values);
            Ok(())
        })
    }
    /// Atomically remove and return a selected dictionary field or list item.
    pub fn take_path(&mut self, path: &[Value]) -> Result<Value> {
        let value = self.get_path(path)?;
        self.delete_path(path)?;
        Ok(value)
    }
    /// Atomically assign `values` to, or delete, a Python slice of a selected list.
    /// Indices follow Python's rules for `start`, `stop`, and a nonzero `step`.
    pub fn slice_path(
        &mut self,
        path: &[Value],
        start: Option<isize>,
        stop: Option<isize>,
        step: isize,
        values: Vec<Value>,
        delete: bool,
    ) -> Result<()> {
        if step == 0 {
            return Err(invalid("slice step cannot be zero"));
        }
        self.edit_list(path, "slice", |items| splice(items, start, stop, step, values, delete))
    }
    /// Apply `edit` to the list a path selects inside one opened group.
    fn edit_list(
        &mut self,
        path: &[Value],
        verb: &str,
        edit: impl FnOnce(&mut Vec<Value>) -> Result<()>,
    ) -> Result<()> {
        let not_a_list = || invalid(format!("{verb} requires a list"));
        let Some((group, inner)) = path.split_first() else {
            return Err(not_a_list());
        };
        self.edit_group(group, |root| edit(descend(root, inner)?.as_array_mut().ok_or_else(not_a_list)?))
    }
    /// The opened group a path's first element names.
    fn opened(&self, group: &Value) -> Result<&Map<String, Value>> {
        group
            .as_str()
            .and_then(|name| self.groups.get(name))
            .ok_or_else(|| invalid("data path not found"))
    }
    /// Apply `edit` to a copy of one opened group; validate and store it only on success.
    fn edit_group(&mut self, group: &Value, edit: impl FnOnce(&mut Value) -> Result<()>) -> Result<()> {
        let name = group.as_str().ok_or_else(|| invalid("data path not found"))?.to_owned();
        let mut root = Value::Object(self.opened(group)?.clone());
        edit(&mut root)?;
        let Value::Object(fields) = root else {
            unreachable!("an edit below a group never replaces the group itself")
        };
        for field in fields.keys() {
            validate_field(field)?;
        }
        self.groups.insert(name, fields);
        self.changed();
        Ok(())
    }
}

/// Set `key` of `parent`, a dictionary key or an existing list index.
fn assign(parent: &mut Value, key: &Value, value: Value) -> Result<()> {
    match (parent, key) {
        (Value::Object(map), Value::String(name)) => {
            map.insert(name.clone(), value);
        }
        (Value::Array(items), Value::Number(index)) => {
            let i = list_index(index).ok_or_else(|| invalid("list index must be nonnegative"))?;
            *items
                .get_mut(i)
                .ok_or_else(|| invalid("list index out of range"))? = value;
        }
        _ => return Err(not_a_key_or_index()),
    }
    Ok(())
}

/// Python's slice assignment or deletion on one list; `step` is nonzero.
fn splice(
    items: &mut Vec<Value>,
    start: Option<isize>,
    stop: Option<isize>,
    step: isize,
    values: Vec<Value>,
    delete: bool,
) -> Result<()> {
    let n = items.len() as isize;
    let bound = |value: Option<isize>, default: isize| {
        value
            .map(|v| if v < 0 { n.saturating_add(v) } else { v })
            .unwrap_or(default)
            .clamp(if step > 0 { 0 } else { -1 }, if step > 0 { n } else { n - 1 })
    };
    let start = bound(start, if step > 0 { 0 } else { n - 1 });
    let stop = bound(stop, if step > 0 { n } else { -1 });
    if step == 1 {
        let replacement = if delete { Vec::new() } else { values };
        items.splice(start as usize..stop.max(start) as usize, replacement);
        return Ok(());
    }
    let mut indices = Vec::new();
    let mut i = start;
    while if step > 0 { i < stop } else { i > stop } {
        indices.push(i as usize);
        match i.checked_add(step) {
            Some(next) => i = next,
            None => break,
        }
    }
    if delete {
        indices.sort_unstable_by(|a, b| b.cmp(a));
        for i in indices {
            items.remove(i);
        }
        return Ok(());
    }
    if indices.len() != values.len() {
        return Err(invalid("extended slice assignment requires matching lengths"));
    }
    for (i, value) in indices.into_iter().zip(values) {
        items[i] = value;
    }
    Ok(())
}

fn not_a_key_or_index() -> crate::Error {
    invalid("path does not address a dictionary key or list index")
}

fn list_index(index: &serde_json::Number) -> Option<usize> {
    index.as_u64().and_then(|n| usize::try_from(n).ok())
}

pub(super) fn business_group(name: &str) -> Result<()> {
    validate_group(name)?;
    if name == GOVERNANCE_GROUP {
        return Err(invalid(
            "policy is retained by the governed object; attach additional policy explicitly",
        ));
    }
    Ok(())
}

fn child<'a>(node: &'a Value, key: &Value) -> Result<&'a Value> {
    match (node, key) {
        (Value::Object(map), Value::String(name)) => map.get(name),
        (Value::Array(items), Value::Number(index)) => list_index(index).and_then(|i| items.get(i)),
        _ => None,
    }
    .ok_or_else(|| invalid("data path not found"))
}

fn descend<'a>(mut node: &'a mut Value, path: &[Value]) -> Result<&'a mut Value> {
    for key in path {
        node = match (node, key) {
            (Value::Object(map), Value::String(name)) => map.get_mut(name),
            (Value::Array(items), Value::Number(index)) => {
                list_index(index).and_then(|i| items.get_mut(i))
            }
            _ => None,
        }
        .ok_or_else(|| invalid("data path not found"))?;
    }
    Ok(node)
}
