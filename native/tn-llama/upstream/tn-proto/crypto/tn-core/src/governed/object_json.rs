//! The one JSON reading of every object TN admits: duplicate member names are refused.
use std::fmt;

use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use super::invalid;
use crate::Result;

// A single interpretation of every JSON object, including AAD and decrypted
// policy values, is part of admission. serde_json::Value alone keeps the last
// duplicate member; this visitor requires each name to occur once.
pub(super) fn parse_json(source: &str) -> Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_str(source);
    let value = UniqueValue::deserialize(&mut deserializer)
        .map_err(|e| invalid(format!("invalid JSON: {e}")))?;
    deserializer
        .end()
        .map_err(|e| invalid(format!("invalid JSON: {e}")))?;
    Ok(value.0)
}

struct UniqueValue(Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueVisitor)
    }
}

struct UniqueVisitor;
impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = UniqueValue;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON with unique object keys")
    }
    fn visit_bool<E>(self, v: bool) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(v)))
    }
    fn visit_i64<E>(self, v: i64) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(v.into()))
    }
    fn visit_u64<E>(self, v: u64) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(v.into()))
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Self::Value, E> {
        serde_json::Number::from_f64(v)
            .map(|n| UniqueValue(Value::Number(n)))
            .ok_or_else(|| E::custom("nonfinite number"))
    }
    fn visit_str<E>(self, v: &str) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(v.into()))
    }
    fn visit_string<E>(self, v: String) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(v.into()))
    }
    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }
    fn visit_seq<A: SeqAccess<'de>>(
        self,
        mut a: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = a.next_element::<UniqueValue>()? {
            values.push(value.0);
        }
        Ok(UniqueValue(Value::Array(values)))
    }
    fn visit_map<A: MapAccess<'de>>(
        self,
        mut a: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = a.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom(format!("duplicate key {key:?}")));
            }
            values.insert(key, a.next_value::<UniqueValue>()?.0);
        }
        Ok(UniqueValue(Value::Object(values)))
    }
}
