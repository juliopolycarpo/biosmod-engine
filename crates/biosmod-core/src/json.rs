//! Strict JSON decoding: duplicate object keys are rejected before typed parsing.
//!
//! Example: `let board: Board = json::parse_strict(&bytes, "boards/x.json")?;`

use crate::error::{Code, Error, Result};
use serde::de::{self, DeserializeOwned, Deserializer, MapAccess, SeqAccess, Visitor};
use std::collections::BTreeSet;
use std::fmt;

/// Parse `bytes` as `T`, rejecting duplicate keys, trailing data and unknown fields
/// (when `T` denies them). `what` names the input in errors.
pub fn parse_strict<T: DeserializeOwned>(bytes: &[u8], what: &str) -> Result<T> {
    check_duplicates(bytes).map_err(|e| e.context(what))?;
    serde_json::from_slice(bytes)
        .map_err(|e| Error::new(Code::CatalogInvalid, format!("{what}: {e}")))
}

/// Reject any JSON object that repeats a key, at any depth.
pub fn check_duplicates(bytes: &[u8]) -> Result<()> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    deserializer
        .deserialize_any(UniqueKeys)
        .and_then(|()| deserializer.end())
        .map_err(|e| Error::new(Code::CatalogInvalid, e.to_string()))
}

struct UniqueKeys;

impl<'de> de::Deserialize<'de> for UniqueKeys {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        deserializer
            .deserialize_any(UniqueKeys)
            .map(|()| UniqueKeys)
    }
}

impl<'de> Visitor<'de> for UniqueKeys {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<(), A::Error> {
        while seq.next_element::<UniqueKeys>()?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<(), A::Error> {
        let mut seen = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom(format!(
                    "duplicate key {key:?}: expected each object key once"
                )));
            }
            map.next_value::<UniqueKeys>()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_keys_are_rejected_at_any_depth() {
        assert!(check_duplicates(br#"{"a":1,"b":{"c":[{"d":1}]}}"#).is_ok());
        let error = check_duplicates(br#"{"a":{"x":1,"x":2}}"#).unwrap_err();
        assert!(error.message.contains("duplicate key \"x\""), "{error}");
    }

    #[test]
    fn trailing_data_is_rejected() {
        assert!(check_duplicates(br#"{"a":1} {"b":2}"#).is_err());
    }
}
