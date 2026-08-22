//! Building witness JSON documents.
//!
//! [`CircuitDescriptor::prove`](zerostyl_circuits::CircuitDescriptor::prove)
//! takes a JSON object whose values are strings — decimal (`"1234"`) or
//! `0x`-prefixed little-endian hex for field elements — and arrays of such
//! strings for Merkle paths. [`WitnessBuilder`] assembles that document.

use std::collections::BTreeMap;

use zerostyl_circuits::{FieldType, WitnessSchema};

use crate::error::{Result, SdkError};

#[derive(Debug, Clone, PartialEq, Eq)]
enum WitnessValue {
    Scalar(String),
    Array(Vec<String>),
}

/// Builder for the witness JSON a circuit descriptor consumes.
///
/// Field order does not matter; descriptors look fields up by name.
#[derive(Debug, Clone, Default)]
pub struct WitnessBuilder {
    fields: BTreeMap<String, WitnessValue>,
}

impl WitnessBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set an unsigned 64-bit value (encoded as a decimal string).
    pub fn set_u64(mut self, name: &str, value: u64) -> Self {
        self.fields.insert(name.into(), WitnessValue::Scalar(value.to_string()));
        self
    }

    /// Set an unsigned 128-bit value (encoded as a decimal string).
    pub fn set_u128(mut self, name: &str, value: u128) -> Self {
        self.fields.insert(name.into(), WitnessValue::Scalar(value.to_string()));
        self
    }

    /// Set a boolean value (encoded as `"0"` / `"1"`).
    pub fn set_bool(mut self, name: &str, value: bool) -> Self {
        let s = if value { "1" } else { "0" };
        self.fields.insert(name.into(), WitnessValue::Scalar(s.into()));
        self
    }

    /// Set a field element from its 32-byte little-endian representation
    /// (`Fr::to_repr()`), encoded as `0x`-hex.
    pub fn set_hex(mut self, name: &str, repr: [u8; 32]) -> Self {
        self.fields.insert(name.into(), WitnessValue::Scalar(crate::inputs::fr_hex(&repr)));
        self
    }

    /// Set a raw pre-encoded string value (decimal or `0x`-hex).
    pub fn set_raw(mut self, name: &str, value: &str) -> Self {
        self.fields.insert(name.into(), WitnessValue::Scalar(value.into()));
        self
    }

    /// Set an array of field elements from little-endian representations.
    pub fn set_array_hex(mut self, name: &str, reprs: &[[u8; 32]]) -> Self {
        let values = reprs.iter().map(crate::inputs::fr_hex).collect();
        self.fields.insert(name.into(), WitnessValue::Array(values));
        self
    }

    /// Set an array of unsigned 64-bit values (decimal strings).
    pub fn set_array_u64(mut self, name: &str, values: &[u64]) -> Self {
        let values = values.iter().map(u64::to_string).collect();
        self.fields.insert(name.into(), WitnessValue::Array(values));
        self
    }

    /// Serialize the witness document.
    pub fn build(&self) -> String {
        let map: serde_json::Map<String, serde_json::Value> = self
            .fields
            .iter()
            .map(|(name, value)| {
                let json = match value {
                    WitnessValue::Scalar(s) => serde_json::Value::String(s.clone()),
                    WitnessValue::Array(items) => serde_json::Value::Array(
                        items.iter().map(|s| serde_json::Value::String(s.clone())).collect(),
                    ),
                };
                (name.clone(), json)
            })
            .collect();
        serde_json::Value::Object(map).to_string()
    }

    /// Serialize after checking the document against a witness schema:
    /// every schema field must be present, and scalar/array shape must match.
    pub fn build_checked(&self, schema: &WitnessSchema) -> Result<String> {
        for field in &schema.fields {
            let value = self.fields.get(&field.name).ok_or_else(|| {
                SdkError::Witness(format!("missing witness field `{}`", field.name))
            })?;
            let is_array_kind = matches!(field.kind, FieldType::Array { .. });
            match value {
                WitnessValue::Scalar(_) if is_array_kind => {
                    return Err(SdkError::Witness(format!(
                        "witness field `{}` expects an array, got a scalar",
                        field.name
                    )));
                }
                WitnessValue::Array(_) if !is_array_kind => {
                    return Err(SdkError::Witness(format!(
                        "witness field `{}` expects a scalar, got an array",
                        field.name
                    )));
                }
                _ => {}
            }
        }
        Ok(self.build())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerostyl_circuits::{FieldVisibility, WitnessField};

    fn schema(fields: Vec<(&str, FieldType)>) -> WitnessSchema {
        WitnessSchema {
            fields: fields
                .into_iter()
                .map(|(name, kind)| WitnessField {
                    name: name.into(),
                    kind,
                    visibility: FieldVisibility::Private,
                    description: None,
                })
                .collect(),
        }
    }

    #[test]
    fn builds_scalar_fields_as_strings() {
        let json = WitnessBuilder::new()
            .set_u64("a", 42)
            .set_u128("b", 1 << 100)
            .set_bool("c", true)
            .build();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["a"], "42");
        assert_eq!(value["b"], (1u128 << 100).to_string());
        assert_eq!(value["c"], "1");
    }

    #[test]
    fn builds_hex_fields_little_endian() {
        let mut repr = [0u8; 32];
        repr[0] = 0x2a;
        let json = WitnessBuilder::new().set_hex("x", repr).build();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let hex = value["x"].as_str().unwrap();
        assert!(hex.starts_with("0x2a"));
        assert_eq!(hex.len(), 2 + 64);
    }

    #[test]
    fn builds_arrays() {
        let json = WitnessBuilder::new().set_array_u64("path", &[1, 2, 3]).build();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["path"], serde_json::json!(["1", "2", "3"]));
    }

    #[test]
    fn checked_accepts_matching_schema() {
        let schema = schema(vec![
            ("a", FieldType::U64),
            ("path", FieldType::Array { kind: Box::new(FieldType::Fp), len: 3 }),
        ]);
        let result = WitnessBuilder::new()
            .set_u64("a", 7)
            .set_array_u64("path", &[1, 2, 3])
            .build_checked(&schema);
        assert!(result.is_ok());
    }

    #[test]
    fn checked_rejects_missing_field() {
        let schema = schema(vec![("a", FieldType::U64)]);
        let err = WitnessBuilder::new().build_checked(&schema).unwrap_err();
        assert!(format!("{err}").contains("missing witness field `a`"));
    }

    #[test]
    fn checked_rejects_shape_mismatch() {
        let schema =
            schema(vec![("path", FieldType::Array { kind: Box::new(FieldType::Fp), len: 2 })]);
        let err = WitnessBuilder::new().set_u64("path", 1).build_checked(&schema).unwrap_err();
        assert!(format!("{err}").contains("expects an array"));
    }

    #[test]
    fn extra_fields_are_allowed() {
        // Descriptors ignore unknown fields (e.g. `_debug` overrides).
        let schema = schema(vec![("a", FieldType::U64)]);
        let result =
            WitnessBuilder::new().set_u64("a", 1).set_u64("_debug_x", 2).build_checked(&schema);
        assert!(result.is_ok());
    }
}
