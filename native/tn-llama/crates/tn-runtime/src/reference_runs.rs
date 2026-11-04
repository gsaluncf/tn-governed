//! Parent references, which publishers write as arithmetic runs when a list is long.
use serde::Deserialize;
use serde_json::{Map, Value};

const REFERENCE_RUNS: &str = "tn.reference-runs.v1";
const MAX_PACKED_REFERENCES: u64 = 1 << 24;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Subject {
    pub object_id: String,
    pub group: String,
    pub field: String,
}

fn expand_run(run: &Map<String, Value>, subjects: &mut [Option<Subject>]) -> Option<()> {
    let text = |name: &str| run.get(name)?.as_str().map(str::to_owned);
    let number = |name: &str| run.get(name)?.as_u64();
    let (object_id, group, prefix) = (text("object_id")?, text("group")?, text("prefix")?);
    let (position, length, stride) = (number("position")?, number("length")?, number("stride")?);
    let first = run.get("number")?;
    for index in 0..length {
        let offset = position.checked_add(index.checked_mul(stride)?)?;
        let slot = subjects.get_mut(usize::try_from(offset).ok()?)?;
        let field = match first.as_u64() {
            Some(first) => format!("{prefix}{}", first.checked_add(index)?),
            None if first.is_null() => prefix.clone(),
            None => return None,
        };
        let subject = Subject {
            object_id: object_id.clone(),
            group: group.clone(),
            field,
        };
        if slot.replace(subject).is_some() {
            return None;
        }
    }
    Some(())
}

/// The exact parent list, or `None` when the value is neither a list nor valid runs.
pub(crate) fn parent_subjects(value: &Value) -> Option<Vec<Subject>> {
    if value.is_array() {
        return serde_json::from_value(value.clone()).ok();
    }
    let packed = value.as_object()?;
    if packed.get("schema")?.as_str()? != REFERENCE_RUNS {
        return None;
    }
    let count = packed.get("count")?.as_u64()?;
    if count > MAX_PACKED_REFERENCES {
        return None;
    }
    let mut subjects = vec![None; usize::try_from(count).ok()?];
    for run in packed.get("runs")?.as_array()? {
        expand_run(run.as_object()?, &mut subjects)?;
    }
    subjects.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn subject(object_id: &str, row: u64) -> Subject {
        Subject {
            object_id: object_id.into(),
            group: "values".into(),
            field: format!("value_{row}"),
        }
    }

    fn run(object_id: &str, position: u64, length: u64) -> Value {
        json!({"object_id":object_id, "group":"values", "prefix":"value_", "number":0,
               "position":position, "length":length, "stride":2})
    }

    fn packed(count: u64, runs: Value) -> Value {
        json!({"schema":REFERENCE_RUNS, "count":count, "runs":runs})
    }

    #[test]
    fn interleaved_runs_restore_the_exact_list() {
        let value = packed(4, json!([run("a", 0, 2), run("b", 1, 2)]));
        let expected = vec![
            subject("a", 0),
            subject("b", 0),
            subject("a", 1),
            subject("b", 1),
        ];
        assert_eq!(parent_subjects(&value), Some(expected));
    }

    #[test]
    fn plain_lists_keep_their_closed_shape() {
        let list = json!([{"object_id":"a", "group":"values", "field":"value_0"}]);
        assert_eq!(parent_subjects(&list), Some(vec![subject("a", 0)]));
        let extra = json!([{"object_id":"a", "group":"values", "field":"value_0", "more":1}]);
        assert_eq!(parent_subjects(&extra), None);
    }

    #[test]
    fn gaps_overlaps_and_other_schemas_are_refused() {
        for value in [
            packed(4, json!([run("a", 0, 2)])),
            packed(4, json!([run("a", 0, 2), run("b", 0, 2)])),
            packed(2, json!([run("a", 0, 2)])),
            packed(u64::MAX, json!([])),
            json!({"schema":"other", "count":0, "runs":[]}),
            json!("value_0"),
        ] {
            assert_eq!(parent_subjects(&value), None, "{value}");
        }
    }
}
